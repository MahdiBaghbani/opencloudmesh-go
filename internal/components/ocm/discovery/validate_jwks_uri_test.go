package discovery

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestValidateDiscoveryJwksUri(t *testing.T) {
	const httpsOrigin = "https://peer.example.com"

	httpSigDisc := func(jwksURI string) *spec.Discovery {
		return &spec.Discovery{
			Capabilities: []string{spec.CapabilityHTTPSig},
			JwksUri:      jwksURI,
		}
	}

	tests := []struct {
		name    string
		jwksURI string
		origin  string
		wantErr string
	}{
		{
			name:    "absent jwksUri with http-sig capability is allowed",
			jwksURI: "",
			origin:  httpsOrigin,
		},
		{
			name:    "well-known path on discovery authority",
			jwksURI: "https://peer.example.com/.well-known/jwks.json",
			origin:  httpsOrigin,
		},
		{
			name:    "custom path on discovery authority",
			jwksURI: "https://peer.example.com/ocm/jwks",
			origin:  httpsOrigin,
		},
		{
			name:    "custom base path and query on discovery authority",
			jwksURI: "https://peer.example.com/base/keys/jwks.json?v=2",
			origin:  httpsOrigin,
		},
		{
			name:    "default https port matches discovery authority",
			jwksURI: "https://peer.example.com:443/jwks",
			origin:  httpsOrigin,
		},
		{
			name:    "relative URL rejected",
			jwksURI: "/.well-known/jwks.json",
			origin:  httpsOrigin,
			wantErr: "must be absolute",
		},
		{
			name:    "scheme-relative URL rejected",
			jwksURI: "//peer.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "must be absolute",
		},
		{
			name:    "malformed URL rejected",
			jwksURI: "https://peer.example.com/%zz",
			origin:  httpsOrigin,
			wantErr: "malformed",
		},
		{
			name:    "non-http scheme rejected",
			jwksURI: "ftp://peer.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "scheme",
		},
		{
			name:    "http rejected with https discovery origin",
			jwksURI: "http://peer.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "must use https",
		},
		{
			name:    "http allowed with explicit development http origin",
			jwksURI: "http://peer.example.com:8080/custom/jwks",
			origin:  "http://peer.example.com:8080",
		},
		{
			name:    "credentials rejected",
			jwksURI: "https://user:pass@peer.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "credentials",
		},
		{
			name:    "opaque credential-bearing URI rejected",
			jwksURI: "https:user:pass@peer.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "must be absolute",
		},
		{
			name:    "fragment rejected",
			jwksURI: "https://peer.example.com/jwks#key-1",
			origin:  httpsOrigin,
			wantErr: "fragment",
		},
		{
			name:    "bare fragment delimiter rejected",
			jwksURI: "https://peer.example.com/jwks#",
			origin:  httpsOrigin,
			wantErr: "fragment",
		},
		{
			name:    "cross-authority host rejected",
			jwksURI: "https://other.example.com/jwks",
			origin:  httpsOrigin,
			wantErr: "authority",
		},
		{
			name:    "cross-authority non-default port rejected",
			jwksURI: "https://peer.example.com:444/jwks",
			origin:  httpsOrigin,
			wantErr: "authority",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiscoveryJwksUri(httpSigDisc(tt.jwksURI), tt.origin)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateDiscoveryJwksUri(%q, %q) error = %v, want nil", tt.jwksURI, tt.origin, err)
				}

				return
			}

			if err == nil {
				t.Fatalf("validateDiscoveryJwksUri(%q, %q) error = nil, want %q", tt.jwksURI, tt.origin, tt.wantErr)
			}

			msg := err.Error()
			if !strings.Contains(msg, tt.wantErr) {
				t.Fatalf("validateDiscoveryJwksUri(%q, %q) error = %q, want substring %q", tt.jwksURI, tt.origin, err, tt.wantErr)
			}

			// Credential and malformed inputs must not leak raw URI text.
			if strings.Contains(tt.jwksURI, "user:pass") {
				if strings.Contains(msg, "user:pass") || strings.Contains(msg, "user@") {
					t.Fatalf("validateDiscoveryJwksUri error = %q, must not echo credential userinfo", msg)
				}
			}

			if strings.Contains(tt.jwksURI, "%zz") {
				if strings.Contains(msg, tt.jwksURI) || strings.Contains(msg, "%zz") {
					t.Fatalf("validateDiscoveryJwksUri error = %q, must not echo raw malformed URI", msg)
				}
			}
		})
	}
}

func TestValidateDiscoveryJwksUri_PresentWithoutHTTPSigCapability(t *testing.T) {
	disc := &spec.Discovery{
		JwksUri: "https://peer.example.com/custom/jwks",
	}

	if err := validateDiscoveryJwksUri(disc, "https://peer.example.com"); err != nil {
		t.Fatalf("jwksUri without http-sig capability should validate on its own merits, got %v", err)
	}
}
