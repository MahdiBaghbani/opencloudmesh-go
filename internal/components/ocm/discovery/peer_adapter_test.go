package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestPeerDiscoveryAdapter_IsSigningCapableFollowsCriteria(t *testing.T) {
	tests := []struct {
		name     string
		criteria []string
		want     bool
	}{
		{
			name:     "capability without criterion is not treated as required signing",
			criteria: nil,
			want:     false,
		},
		{
			name:     "criterion marks peer as requiring signed requests",
			criteria: []string{"http-request-signatures"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/ocm", "/ocm-provider":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(Discovery{
						Enabled:      true,
						APIVersion:   "1.2.2",
						EndPoint:     srv.URL + "/ocm",
						Capabilities: []string{"http-sig"},
						Criteria:     tt.criteria,
						PublicKeys:   []PublicKey{{KeyID: "key1", PublicKeyPem: "pem"}},
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			outboundCfg := &config.OutboundHTTPConfig{
				SSRFMode:           "off",
				MaxResponseBytes:   1 << 20,
				InsecureSkipVerify: false,
			}
			client := NewClient(httpclient.New(outboundCfg, nil), nil)
			adapter := NewPeerDiscoveryAdapter(client)

			got, err := adapter.IsSigningCapable(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("IsSigningCapable() unexpected error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("IsSigningCapable() = %v, want %v", got, tt.want)
			}
		})
	}
}
