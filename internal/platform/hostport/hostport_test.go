package hostport

import (
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		scheme    string
		want      string
		wantErr   bool
	}{
		// Default port stripping
		{"https default port stripped", "example.org:443", "https", "example.org", false},
		{"http default port stripped", "example.org:80", "http", "example.org", false},
		{"https non-default port kept", "example.org:8443", "https", "example.org:8443", false},
		{"http non-default port kept", "example.org:8080", "http", "example.org:8080", false},

		// Equivalence: bare host equals host with default port
		{"https bare host", "example.org", "https", "example.org", false},
		{"http bare host", "example.org", "http", "example.org", false},

		// Cross-scheme: 443 is not default for http
		{"port 443 for http scheme", "example.org:443", "http", "example.org:443", false},
		{"port 80 for https scheme", "example.org:80", "https", "example.org:80", false},

		// Case insensitivity
		{"uppercase host lowercased", "EXAMPLE.ORG", "https", "example.org", false},
		{"mixed case host lowercased", "Example.Org:9200", "https", "example.org:9200", false},

		// IPv6
		{"ipv6 bare", "[::1]", "https", "[::1]", false},
		{"ipv6 with port", "[::1]:9200", "https", "[::1]:9200", false},
		{"ipv6 default https port stripped", "[::1]:443", "https", "[::1]", false},
		{"ipv6 default http port stripped", "[::1]:80", "http", "[::1]", false},

		// Whitespace trimming
		{"leading whitespace trimmed", "  example.org", "https", "example.org", false},
		{"trailing whitespace trimmed", "example.org  ", "https", "example.org", false},

		// Rejection: scheme in authority
		{"reject scheme in authority", "https://example.org", "https", "", true},
		{"reject http scheme in authority", "http://example.org", "https", "", true},

		// Rejection: path in authority
		{"reject path in authority", "example.org/path", "https", "", true},

		// Rejection: empty
		{"reject empty", "", "https", "", true},
		{"reject whitespace only", "   ", "https", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(tt.authority, tt.scheme)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Normalize(%q, %q) error = %v, wantErr = %v", tt.authority, tt.scheme, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Normalize(%q, %q) = %q, want %q", tt.authority, tt.scheme, got, tt.want)
			}
		})
	}
}

func TestNormalize_Equivalence(t *testing.T) {
	// Verify that bare host and host with default port produce the same result.
	bare, err1 := Normalize("example.org", "https")
	withPort, err2 := Normalize("example.org:443", "https")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected error: bare=%v, withPort=%v", err1, err2)
	}
	if bare != withPort {
		t.Errorf("expected equivalent: %q != %q", bare, withPort)
	}

	bare, err1 = Normalize("example.org", "http")
	withPort, err2 = Normalize("example.org:80", "http")
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected error: bare=%v, withPort=%v", err1, err2)
	}
	if bare != withPort {
		t.Errorf("expected equivalent: %q != %q", bare, withPort)
	}
}
