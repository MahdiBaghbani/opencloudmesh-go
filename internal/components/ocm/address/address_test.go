package address

import (
	"encoding/base64"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		wantID     string
		wantProv   string
		wantErr    bool
	}{
		{
			name:     "simple user@host",
			addr:     "alice@example.org",
			wantID:   "alice",
			wantProv: "example.org",
		},
		{
			name:     "user@host:port",
			addr:     "alice@example.org:9200",
			wantID:   "alice",
			wantProv: "example.org:9200",
		},
		{
			name:     "email identifier (last-@ semantics)",
			addr:     "alice@example.org@provider.net",
			wantID:   "alice@example.org",
			wantProv: "provider.net",
		},
		{
			name:     "email identifier with port",
			addr:     "alice@example.org@provider.net:443",
			wantID:   "alice@example.org",
			wantProv: "provider.net:443",
		},
		{
			name:     "base64 encoded identifier with @",
			addr:     "dXNlcg==@host.example",
			wantID:   "dXNlcg==",
			wantProv: "host.example",
		},
		{
			name:     "IPv6 provider",
			addr:     "alice@[::1]:9200",
			wantID:   "alice",
			wantProv: "[::1]:9200",
		},
		{
			name:    "empty string",
			addr:    "",
			wantErr: true,
		},
		{
			name:    "no @ separator",
			addr:    "bareidentifier",
			wantErr: true,
		},
		{
			name:    "empty identifier (starts with @)",
			addr:    "@example.org",
			wantErr: true,
		},
		{
			name:    "empty provider (ends with @)",
			addr:    "alice@",
			wantErr: true,
		},
		{
			name:    "scheme in provider",
			addr:    "alice@https://example.org",
			wantErr: true,
		},
		{
			name:    "path in provider",
			addr:    "alice@example.org/path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, prov, err := Parse(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse(%q) expected error, got id=%q prov=%q", tt.addr, id, prov)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.addr, err)
			}
			if id != tt.wantID {
				t.Errorf("Parse(%q) identifier = %q, want %q", tt.addr, id, tt.wantID)
			}
			if prov != tt.wantProv {
				t.Errorf("Parse(%q) provider = %q, want %q", tt.addr, prov, tt.wantProv)
			}
		})
	}
}

func TestFormatOutgoing(t *testing.T) {
	tests := []struct {
		name         string
		userID       string
		providerFQDN string
		want         string
	}{
		{
			name:         "uuid user id",
			userID:       "550e8400-e29b-41d4-a716-446655440000",
			providerFQDN: "example.org",
			want:         base64.StdEncoding.EncodeToString([]byte("550e8400-e29b-41d4-a716-446655440000")) + "@example.org",
		},
		{
			name:         "simple user id",
			userID:       "alice",
			providerFQDN: "provider.net:9200",
			want:         base64.StdEncoding.EncodeToString([]byte("alice")) + "@provider.net:9200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatOutgoing(tt.userID, tt.providerFQDN)
			if got != tt.want {
				t.Errorf("FormatOutgoing(%q, %q) = %q, want %q", tt.userID, tt.providerFQDN, got, tt.want)
			}
		})
	}
}

func TestFormatOutgoing_RoundTrip(t *testing.T) {
	// FormatOutgoing produces an OCM address that Parse can split back
	userID := "550e8400-e29b-41d4-a716-446655440000"
	provider := "example.org"

	addr := FormatOutgoing(userID, provider)
	id, prov, err := Parse(addr)
	if err != nil {
		t.Fatalf("Parse(FormatOutgoing(%q, %q)) error: %v", userID, provider, err)
	}

	if prov != provider {
		t.Errorf("round-trip provider = %q, want %q", prov, provider)
	}

	// The identifier should be the base64-encoded userID
	decoded, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("base64 decode of identifier %q failed: %v", id, err)
	}
	if string(decoded) != userID {
		t.Errorf("round-trip userID = %q, want %q", string(decoded), userID)
	}
}
