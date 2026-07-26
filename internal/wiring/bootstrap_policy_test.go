package wiring_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestBuild_SignaturePolicyWiredFromCodeFlow(t *testing.T) {
	tests := []struct {
		name     string
		requires bool
		wantCode int
	}{
		{
			name:     "requires true with key present rejects unsigned",
			requires: true,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "requires false with key present allows unsigned",
			requires: false,
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DevConfig()
			cfg.Signature.KeyPath = filepath.Join(t.TempDir(), "signing.pem")

			requires := tt.requires
			cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = &requires

			opts := harnessBuildOpts()
			opts.SkipCrypto = false

			result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			mw := result.Deps.SignatureMiddleware
			if mw == nil {
				t.Fatal("SignatureMiddleware must be non-nil")
			}

			peerResolver := func(r *http.Request, body []byte) (string, error) {
				return "sender.example.com", nil
			}
			handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			)

			body := []byte(`{"test":"data"}`)
			req := httptest.NewRequest(
				http.MethodPost,
				"https://localhost:9200/ocm/shares",
				bytes.NewReader(body),
			)
			req.Host = "localhost:9200"
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body = %q",
					w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}
