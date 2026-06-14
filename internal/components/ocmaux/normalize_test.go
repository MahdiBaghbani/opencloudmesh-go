package ocmaux

import "testing"

func TestNormalizeToOrigin(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "trim whitespace", input: "  https://example.com/path  ", want: "https://example.com"},
		{name: "bare host defaults https", input: "example.com", want: "https://example.com"},
		{name: "bare host with path", input: "example.com/apps/files", want: "https://example.com"},
		{name: "preserve http scheme", input: "http://example.com/foo", want: "http://example.com"},
		{name: "preserve non-default port", input: "https://example.com:8443/ocm", want: "https://example.com:8443"},
		{name: "bare host with port", input: "example.com:9443/share", want: "https://example.com:9443"},
		{name: "ipv6 with port", input: "https://[::1]:8080/ui", want: "https://[::1]:8080"},
		{name: "ftp rejected", input: "ftp://example.com", wantErr: true},
		{name: "empty", input: "   ", wantErr: true},
		{name: "missing host", input: "https://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeToOrigin(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeToOrigin(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeToOrigin(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
