package keyid_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
)

// TestParse_AllFormats covers every keyId format found in the wild.
// See plan "keyId format test coverage" table for origins.
func TestParse_AllFormats(t *testing.T) {
	tests := []struct {
		name             string
		keyID            string
		expectedScheme   string
		expectedHostname string
		expectedPort     string
	}{
		{
			name:             "opencloudmesh-go (RFC 9421)",
			keyID:            "https://example.com/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "Nextcloud root (legacy)",
			keyID:            "https://example.com/ocm#signature",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "Nextcloud subfolder",
			keyID:            "https://example.com/nextcloud/ocm#signature",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "OCM-rs (well-known path)",
			keyID:            "https://example.com/.well-known/ocm#signature",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "Amity (no path, fragment only)",
			keyID:            "https://example.com#main-key",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "OCM-API spec legacy",
			keyID:            "https://cloud.example.org/ocm#signature",
			expectedScheme:   "https",
			expectedHostname: "cloud.example.org",
			expectedPort:     "",
		},
		{
			name:             "OCM-API spec RFC 9421",
			keyID:            "https://cloud.example.org/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "cloud.example.org",
			expectedPort:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := keyid.Parse(tt.keyID)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.keyID, err)
			}

			if p.Scheme != tt.expectedScheme {
				t.Errorf("Scheme: got %q, want %q", p.Scheme, tt.expectedScheme)
			}
			if p.Hostname != tt.expectedHostname {
				t.Errorf("Hostname: got %q, want %q", p.Hostname, tt.expectedHostname)
			}
			if p.Port != tt.expectedPort {
				t.Errorf("Port: got %q, want %q", p.Port, tt.expectedPort)
			}
		})
	}
}

// TestParse_EdgeCases covers ports, IPv6, and http scheme.
func TestParse_EdgeCases(t *testing.T) {
	tests := []struct {
		name             string
		keyID            string
		expectedScheme   string
		expectedHostname string
		expectedPort     string
	}{
		{
			name:             "explicit port",
			keyID:            "https://example.com:9200/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "9200",
		},
		{
			name:             "explicit default port 443",
			keyID:            "https://example.com:443/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "443",
		},
		{
			name:             "explicit default port 80",
			keyID:            "http://example.com:80/ocm#key-1",
			expectedScheme:   "http",
			expectedHostname: "example.com",
			expectedPort:     "80",
		},
		{
			name:             "IPv6 with port",
			keyID:            "https://[::1]:9200/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "::1",
			expectedPort:     "9200",
		},
		{
			name:             "IPv6 without port",
			keyID:            "https://[::1]/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "::1",
			expectedPort:     "",
		},
		{
			name:             "http scheme",
			keyID:            "http://example.com/ocm#signature",
			expectedScheme:   "http",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "uppercase host is lowercased",
			keyID:            "https://EXAMPLE.COM/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "",
		},
		{
			name:             "mixed case scheme and host",
			keyID:            "HTTPS://Example.COM:9200/ocm#key-1",
			expectedScheme:   "https",
			expectedHostname: "example.com",
			expectedPort:     "9200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := keyid.Parse(tt.keyID)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.keyID, err)
			}

			if p.Scheme != tt.expectedScheme {
				t.Errorf("Scheme: got %q, want %q", p.Scheme, tt.expectedScheme)
			}
			if p.Hostname != tt.expectedHostname {
				t.Errorf("Hostname: got %q, want %q", p.Hostname, tt.expectedHostname)
			}
			if p.Port != tt.expectedPort {
				t.Errorf("Port: got %q, want %q", p.Port, tt.expectedPort)
			}
		})
	}
}

// TestParse_Strictness verifies rejection and acceptance rules.
func TestParse_Strictness(t *testing.T) {
	t.Run("rejects userinfo", func(t *testing.T) {
		_, err := keyid.Parse("https://user@example.com/ocm#key-1")
		if err == nil {
			t.Error("expected error for userinfo in keyId")
		}
	})

	t.Run("rejects userinfo with password", func(t *testing.T) {
		_, err := keyid.Parse("https://user:pass@example.com/ocm#key-1")
		if err == nil {
			t.Error("expected error for userinfo with password")
		}
	})

	t.Run("accepts query and ignores it", func(t *testing.T) {
		p, err := keyid.Parse("https://example.com/ocm?x=y#signature")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if p.Hostname != "example.com" {
			t.Errorf("Hostname: got %q, want %q", p.Hostname, "example.com")
		}

		// Authority should not include query
		auth := keyid.Authority(p)
		if auth != "example.com" {
			t.Errorf("Authority: got %q, want %q", auth, "example.com")
		}
	})

	t.Run("rejects no scheme", func(t *testing.T) {
		_, err := keyid.Parse("example.com/ocm#key-1")
		if err == nil {
			t.Error("expected error for missing scheme")
		}
	})

	t.Run("rejects ftp scheme", func(t *testing.T) {
		_, err := keyid.Parse("ftp://example.com/ocm#key-1")
		if err == nil {
			t.Error("expected error for ftp scheme")
		}
	})

	t.Run("rejects no host", func(t *testing.T) {
		_, err := keyid.Parse("https:///ocm#key-1")
		if err == nil {
			t.Error("expected error for missing host")
		}
	})

	t.Run("rejects empty string", func(t *testing.T) {
		_, err := keyid.Parse("")
		if err == nil {
			t.Error("expected error for empty string")
		}
	})
}

// TestAuthority verifies the raw authority string.
func TestAuthority(t *testing.T) {
	tests := []struct {
		name     string
		keyID    string
		expected string
	}{
		{"no port", "https://example.com/ocm#key-1", "example.com"},
		{"with port", "https://example.com:9200/ocm#key-1", "example.com:9200"},
		{"default port preserved", "https://example.com:443/ocm#key-1", "example.com:443"},
		{"IPv6 with port", "https://[::1]:9200/ocm#key-1", "[::1]:9200"},
		{"IPv6 without port", "https://[::1]/ocm#key-1", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := keyid.Parse(tt.keyID)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			got := keyid.Authority(p)
			if got != tt.expected {
				t.Errorf("Authority: got %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestAuthorityForCompareFromKeyID verifies scheme-aware default port stripping.
func TestAuthorityForCompareFromKeyID(t *testing.T) {
	tests := []struct {
		name     string
		keyID    string
		expected string
	}{
		{"https no port", "https://example.com/ocm#key-1", "example.com"},
		{"https with 443 stripped", "https://example.com:443/ocm#key-1", "example.com"},
		{"https with non-default port kept", "https://example.com:9200/ocm#key-1", "example.com:9200"},
		{"http no port", "http://example.com/ocm#signature", "example.com"},
		{"http with 80 stripped", "http://example.com:80/ocm#signature", "example.com"},
		{"http with non-default port kept", "http://example.com:8080/ocm#signature", "example.com:8080"},
		// Cross-scheme: :80 is NOT stripped for https, :443 is NOT stripped for http
		{"https with 80 kept (not default for https)", "https://example.com:80/ocm#key-1", "example.com:80"},
		{"http with 443 kept (not default for http)", "http://example.com:443/ocm#signature", "example.com:443"},
		// IPv6
		{"IPv6 with non-default port", "https://[::1]:9200/ocm#key-1", "[::1]:9200"},
		{"IPv6 with 443 stripped", "https://[::1]:443/ocm#key-1", "[::1]"},
		{"IPv6 without port", "https://[::1]/ocm#key-1", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := keyid.Parse(tt.keyID)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			got := keyid.AuthorityForCompareFromKeyID(p)
			if got != tt.expected {
				t.Errorf("AuthorityForCompareFromKeyID: got %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestAuthorityForCompareFromDeclaredPeer verifies normalization of schemeless
// peer authorities using scheme-aware default port stripping.
func TestAuthorityForCompareFromDeclaredPeer(t *testing.T) {
	tests := []struct {
		name     string
		peer     string
		scheme   string
		expected string
	}{
		{"bare host https", "example.com", "https", "example.com"},
		{"bare host http", "example.com", "http", "example.com"},
		{"host with 443 stripped (https)", "example.com:443", "https", "example.com"},
		{"host with 80 stripped (http)", "example.com:80", "http", "example.com"},
		{"host with 443 kept (http)", "example.com:443", "http", "example.com:443"},
		{"host with 80 kept (https)", "example.com:80", "https", "example.com:80"},
		{"non-default port kept", "example.com:9200", "https", "example.com:9200"},
		{"uppercase host lowercased", "EXAMPLE.COM", "https", "example.com"},
		{"uppercase with port", "EXAMPLE.COM:9200", "https", "example.com:9200"},
		{"IPv6 bare", "[::1]", "https", "[::1]"},
		{"IPv6 with port", "[::1]:9200", "https", "[::1]:9200"},
		{"IPv6 with 443 stripped", "[::1]:443", "https", "[::1]"},
		{"leading whitespace trimmed", "  example.com", "https", "example.com"},
		{"trailing whitespace trimmed", "example.com  ", "https", "example.com"},
		{"both whitespace trimmed", "  example.com  ", "https", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keyid.AuthorityForCompareFromDeclaredPeer(tt.peer, tt.scheme)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.expected {
				t.Errorf("AuthorityForCompareFromDeclaredPeer(%q, %q): got %q, want %q",
					tt.peer, tt.scheme, got, tt.expected)
			}
		})
	}
}

// TestAuthorityForCompareFromDeclaredPeer_Errors verifies error cases.
func TestAuthorityForCompareFromDeclaredPeer_Errors(t *testing.T) {
	tests := []struct {
		name   string
		peer   string
		scheme string
	}{
		{"empty peer", "", "https"},
		{"whitespace only", "   ", "https"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyid.AuthorityForCompareFromDeclaredPeer(tt.peer, tt.scheme)
			if err == nil {
				t.Errorf("expected error for peer %q", tt.peer)
			}
		})
	}
}

// TestSchemeAwareEquivalence verifies that default port equivalence is
// scheme-aware: example.com matches example.com:443 only for https,
// and example.com matches example.com:80 only for http.
func TestSchemeAwareEquivalence(t *testing.T) {
	t.Run("https: bare host equals host:443", func(t *testing.T) {
		p, err := keyid.Parse("https://example.com:443/ocm#key-1")
		if err != nil {
			t.Fatal(err)
		}

		fromKeyID := keyid.AuthorityForCompareFromKeyID(p)
		fromPeer, err := keyid.AuthorityForCompareFromDeclaredPeer("example.com", "https")
		if err != nil {
			t.Fatal(err)
		}

		if fromKeyID != fromPeer {
			t.Errorf("should be equivalent: keyId=%q peer=%q", fromKeyID, fromPeer)
		}
	})

	t.Run("http: bare host equals host:80", func(t *testing.T) {
		p, err := keyid.Parse("http://example.com:80/ocm#signature")
		if err != nil {
			t.Fatal(err)
		}

		fromKeyID := keyid.AuthorityForCompareFromKeyID(p)
		fromPeer, err := keyid.AuthorityForCompareFromDeclaredPeer("example.com", "http")
		if err != nil {
			t.Fatal(err)
		}

		if fromKeyID != fromPeer {
			t.Errorf("should be equivalent: keyId=%q peer=%q", fromKeyID, fromPeer)
		}
	})

	t.Run("https: bare host does NOT equal host:80", func(t *testing.T) {
		p, err := keyid.Parse("https://example.com:80/ocm#key-1")
		if err != nil {
			t.Fatal(err)
		}

		fromKeyID := keyid.AuthorityForCompareFromKeyID(p)
		fromPeer, err := keyid.AuthorityForCompareFromDeclaredPeer("example.com", "https")
		if err != nil {
			t.Fatal(err)
		}

		if fromKeyID == fromPeer {
			t.Errorf("should NOT be equivalent: keyId=%q peer=%q", fromKeyID, fromPeer)
		}
	})

	t.Run("http: bare host does NOT equal host:443", func(t *testing.T) {
		p, err := keyid.Parse("http://example.com:443/ocm#signature")
		if err != nil {
			t.Fatal(err)
		}

		fromKeyID := keyid.AuthorityForCompareFromKeyID(p)
		fromPeer, err := keyid.AuthorityForCompareFromDeclaredPeer("example.com", "http")
		if err != nil {
			t.Fatal(err)
		}

		if fromKeyID == fromPeer {
			t.Errorf("should NOT be equivalent: keyId=%q peer=%q", fromKeyID, fromPeer)
		}
	})

	t.Run("both explicit 443 equal for https", func(t *testing.T) {
		p, err := keyid.Parse("https://example.com:443/ocm#key-1")
		if err != nil {
			t.Fatal(err)
		}

		fromKeyID := keyid.AuthorityForCompareFromKeyID(p)
		fromPeer, err := keyid.AuthorityForCompareFromDeclaredPeer("example.com:443", "https")
		if err != nil {
			t.Fatal(err)
		}

		if fromKeyID != fromPeer {
			t.Errorf("should be equivalent: keyId=%q peer=%q", fromKeyID, fromPeer)
		}
	})
}
