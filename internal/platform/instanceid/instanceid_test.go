package instanceid_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

func TestNormalizeExternalOrigin(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{"https basic", "https://example.com", "https://example.com", false},
		{"http basic", "http://example.com", "http://example.com", false},
		{"trailing slash", "https://example.com/", "https://example.com", false},
		{"uppercase host", "https://EXAMPLE.COM", "https://example.com", false},
		{"uppercase scheme", "HTTPS://example.com", "https://example.com", false},
		{"mixed case", "HTTPS://Example.COM/", "https://example.com", false},
		{"with port", "https://example.com:9200", "https://example.com:9200", false},
		{"default port preserved", "https://example.com:443", "https://example.com:443", false},
		{"http default port preserved", "http://example.com:80", "http://example.com:80", false},
		{"IPv6", "https://[::1]:9200", "https://[::1]:9200", false},
		{"IPv6 no port", "https://[::1]", "https://[::1]", false},
		{"localhost with port", "http://localhost:8080", "http://localhost:8080", false},

		// Error cases
		{"empty", "", "", true},
		{"no scheme", "example.com", "", true},
		{"relative path", "/foo/bar", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := instanceid.NormalizeExternalOrigin(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got result %q", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestProviderFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{"https basic", "https://example.com", "example.com", false},
		{"http basic", "http://example.com", "example.com", false},
		{"with port", "https://example.com:9200", "example.com:9200", false},
		{"default port preserved", "https://example.com:443", "example.com:443", false},
		{"trailing slash", "https://example.com/", "example.com", false},
		{"uppercase", "https://EXAMPLE.COM", "example.com", false},
		{"IPv6 with port", "https://[::1]:9200", "[::1]:9200", false},
		{"IPv6 no port", "https://[::1]", "[::1]", false},
		{"localhost", "http://localhost:8080", "localhost:8080", false},

		// Error cases
		{"empty", "", "", true},
		{"no scheme", "example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := instanceid.ProviderFQDN(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got result %q", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestHostname(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{"https basic", "https://example.com", "example.com", false},
		{"with port", "https://example.com:9200", "example.com", false},
		{"default port", "https://example.com:443", "example.com", false},
		{"uppercase", "https://EXAMPLE.COM:9200", "example.com", false},
		{"IPv6 with port", "https://[::1]:9200", "::1", false},
		{"IPv6 no port", "https://[::1]", "::1", false},
		{"IPv4", "https://192.168.1.1:8080", "192.168.1.1", false},
		{"localhost", "http://localhost:8080", "localhost", false},

		// Error cases
		{"empty", "", "", true},
		{"no scheme", "example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := instanceid.Hostname(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got result %q", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
