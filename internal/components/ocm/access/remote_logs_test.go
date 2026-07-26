package access

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestClient_Access_DoesNotLogSensitiveValues(t *testing.T) {
	tests := []struct {
		name         string
		sharedSecret string
		accessToken  string
	}{
		{
			name:         "primary exchange values",
			sharedSecret: "exchange-code-must-not-log",
			accessToken:  "issued-access-token-must-not-log",
		},
		{
			name:         "second exchange values",
			sharedSecret: "exchange-code-second-must-not-log",
			accessToken:  "issued-access-token-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := logutil.NewCapturingLogger(slog.LevelDebug)
			prev := slog.Default()

			slog.SetDefault(capture.Logger)
			t.Cleanup(func() { slog.SetDefault(prev) })

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ocm/token" {
					_ = r.ParseForm()
					if got := r.FormValue("code"); got != tt.sharedSecret {
						t.Errorf("token exchange code = %q, want %q", got, tt.sharedSecret)
					}
				}

				if exchangeDiscoveryHandler(w, r, tt.accessToken) {
					return
				}

				if r.URL.Path == "/webdav/ocm/file.txt" {
					if got := r.Header.Get("Authorization"); got != "Bearer "+tt.accessToken {
						t.Errorf("WebDAV authorization = %q, want bearer token", got)
					}

					w.WriteHeader(http.StatusOK)

					return
				}

				http.NotFound(w, r)
			}))
			t.Cleanup(srv.Close)

			client := newExchangeAccessClient(t, srv)
			share := &ShareInfo{
				Status:       ShareStatusAccepted,
				SenderHost:   srv.Listener.Addr().String(),
				SharedSecret: tt.sharedSecret,
				Requirements: []string{spec.RequirementMustExchangeToken},
				WebDAVID:     "/webdav/ocm/file.txt",
			}

			result, err := client.Access(context.Background(), AccessOptions{
				Share:    share,
				Protocol: "webdav",
				Method:   http.MethodGet,
			})
			if err != nil {
				t.Fatalf("access failed: %v", err)
			}
			defer result.Response.Body.Close()

			if result.AccessToken != tt.accessToken {
				t.Fatalf("access token = %q, want %q", result.AccessToken, tt.accessToken)
			}

			if capture.ContainsAny(
				tt.sharedSecret,
				tt.accessToken,
				"Authorization",
				"Signature",
				"mock-signature",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}
