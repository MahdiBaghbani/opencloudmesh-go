package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
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
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			outboundCfg := &config.OutboundHTTPConfig{
				DerivedSSRFMode:    "off",
				MaxResponseBytes:   1 << 20,
				InsecureSkipVerify: false,
			}
			rawClient := httpclient.New(outboundCfg, nil)
			client := NewClient(rawClient, nil)
			adapter := NewPeerDiscoveryAdapter(client, rawClient)

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

func TestPeerDiscoveryAdapter_GetPublicKeyFromJWKS(t *testing.T) {
	var srv *httptest.Server
	var km *crypto.KeyManager

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwks.WellKnownPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(km.JWKS())
		case "/.well-known/ocm", "/ocm-provider":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   srv.URL + "/ocm",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"local-http": {
				Name:      "local-http",
				AllowHTTP: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*", Profile: "local-http"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}

	outboundCfg := &config.OutboundHTTPConfig{
		DerivedSSRFMode:    "off",
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	client := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(client, rawClient)
	adapter.SetPeerContract(contract)

	keyID := km.GetKeyID()
	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		t.Fatalf("ParseKid(%q): %v", keyID, err)
	}
	if parsed.Scheme != "" {
		t.Fatalf("expected canonical host#fragment kid, got scheme %q in %q", parsed.Scheme, keyID)
	}

	pem, err := adapter.GetPublicKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	pub, err := crypto.ParsePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if !pub.Equal(km.GetSigningKey().PublicKey) {
		t.Fatal("JWKS public key mismatch")
	}
}

func TestPeerDiscoveryAdapter_GetPublicKey_JWKSErrors(t *testing.T) {
	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"local-http": {
				Name:      "local-http",
				AllowHTTP: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*", Profile: "local-http"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}

	outboundCfg := &config.OutboundHTTPConfig{
		DerivedSSRFMode:    "off",
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	client := NewClient(rawClient, nil)

	t.Run("jwks 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				http.NotFound(w, r)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(client, rawClient)
		adapter.SetPeerContract(contract)

		_, err := adapter.GetPublicKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected jwks lookup error for 404")
		}
	})

	t.Run("invalid jwks JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(client, rawClient)
		adapter.SetPeerContract(contract)

		_, err := adapter.GetPublicKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected jwks decode error")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		var srv *httptest.Server
		otherKM := crypto.NewKeyManager("", "https://other.example.com")
		if err := otherKM.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(otherKM.JWKS())
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(client, rawClient)
		adapter.SetPeerContract(contract)

		_, err := adapter.GetPublicKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected missing kid error")
		}
	})
}
