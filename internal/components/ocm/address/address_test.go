package address

import (
	"encoding/base64"
	"strings"
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

func TestEncodeFederatedOpaqueID(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		idp    string
	}{
		{
			name:   "simple username",
			userID: "alice",
			idp:    "example.org",
		},
		{
			name:   "uuid user id",
			userID: "550e8400-e29b-41d4-a716-446655440000",
			idp:    "provider.net:9200",
		},
		{
			name:   "unknown placeholder",
			userID: "unknown",
			idp:    "localhost:9200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeFederatedOpaqueID(tt.userID, tt.idp)

			if strings.ContainsAny(encoded, "+/") {
				t.Errorf("EncodeFederatedOpaqueID(%q, %q) = %q contains +/ (not base64url)", tt.userID, tt.idp, encoded)
			}

			decoded, err := base64.URLEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("base64url decode of %q failed: %v", encoded, err)
			}

			wantPayload := tt.userID + "@" + tt.idp
			if string(decoded) != wantPayload {
				t.Errorf("decoded payload = %q, want %q", string(decoded), wantPayload)
			}
		})
	}
}

func TestDecodeFederatedOpaqueID(t *testing.T) {
	tests := []struct {
		name       string
		encoded    string
		wantUserID string
		wantIDP    string
		wantOK     bool
	}{
		{
			name:       "padded base64url (canonical emission)",
			encoded:    base64.URLEncoding.EncodeToString([]byte("alice@example.org")),
			wantUserID: "alice",
			wantIDP:    "example.org",
			wantOK:     true,
		},
		{
			name:       "raw base64url (unpadded compat)",
			encoded:    base64.RawURLEncoding.EncodeToString([]byte("bob@provider.net")),
			wantUserID: "bob",
			wantIDP:    "provider.net",
			wantOK:     true,
		},
		{
			name:       "standard base64 (compat)",
			encoded:    base64.StdEncoding.EncodeToString([]byte("carol@host.example")),
			wantUserID: "carol",
			wantIDP:    "host.example",
			wantOK:     true,
		},
		{
			name:       "uuid user id with port in idp",
			encoded:    base64.URLEncoding.EncodeToString([]byte("550e8400-e29b-41d4-a716-446655440000@provider.net:9200")),
			wantUserID: "550e8400-e29b-41d4-a716-446655440000",
			wantIDP:    "provider.net:9200",
			wantOK:     true,
		},
		{
			name:       "email-like user id (last-@ split)",
			encoded:    base64.URLEncoding.EncodeToString([]byte("alice@mail.org@provider.net")),
			wantUserID: "alice@mail.org",
			wantIDP:    "provider.net",
			wantOK:     true,
		},
		{
			name:    "invalid base64",
			encoded: "not-valid-base64!!!",
			wantOK:  false,
		},
		{
			name:    "valid base64 but no @ in payload",
			encoded: base64.URLEncoding.EncodeToString([]byte("noatsign")),
			wantOK:  false,
		},
		{
			name:    "valid base64 but payload starts with @",
			encoded: base64.URLEncoding.EncodeToString([]byte("@provider.net")),
			wantOK:  false,
		},
		{
			name:    "valid base64 but payload ends with @",
			encoded: base64.URLEncoding.EncodeToString([]byte("alice@")),
			wantOK:  false,
		},
		{
			name:    "empty string",
			encoded: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, idp, ok := DecodeFederatedOpaqueID(tt.encoded)
			if ok != tt.wantOK {
				t.Fatalf("DecodeFederatedOpaqueID(%q) ok = %v, want %v", tt.encoded, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if userID != tt.wantUserID {
				t.Errorf("DecodeFederatedOpaqueID(%q) userID = %q, want %q", tt.encoded, userID, tt.wantUserID)
			}
			if idp != tt.wantIDP {
				t.Errorf("DecodeFederatedOpaqueID(%q) idp = %q, want %q", tt.encoded, idp, tt.wantIDP)
			}
		})
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		idp    string
	}{
		{name: "simple", userID: "alice", idp: "example.org"},
		{name: "uuid", userID: "550e8400-e29b-41d4-a716-446655440000", idp: "provider.net:9200"},
		{name: "unknown placeholder", userID: "unknown", idp: "localhost:9200"},
		{name: "special chars in user", userID: "user+tag", idp: "host.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeFederatedOpaqueID(tt.userID, tt.idp)
			gotUserID, gotIDP, ok := DecodeFederatedOpaqueID(encoded)
			if !ok {
				t.Fatalf("DecodeFederatedOpaqueID(EncodeFederatedOpaqueID(%q, %q)) failed", tt.userID, tt.idp)
			}
			if gotUserID != tt.userID {
				t.Errorf("round-trip userID = %q, want %q", gotUserID, tt.userID)
			}
			if gotIDP != tt.idp {
				t.Errorf("round-trip idp = %q, want %q", gotIDP, tt.idp)
			}
		})
	}
}

func TestLooksLikeBase64(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{name: "standard base64 padded", s: "dXNlcg==", want: true},
		{name: "base64url with underscore", s: "dXNlckBpZHA_", want: true},
		{name: "base64url with hyphen", s: "abc-def_ghi", want: true},
		{name: "alphanumeric only", s: "abc123XYZ", want: true},
		{name: "standard base64 with plus and slash", s: "abc+def/ghi=", want: true},
		{name: "email address (contains @)", s: "alice@example.org", want: false},
		{name: "string with spaces", s: "abc def", want: false},
		{name: "string with dot", s: "alice.bob", want: false},
		{name: "string with colon", s: "host:9200", want: false},
		{name: "empty string", s: "", want: false},
		{name: "string with exclamation", s: "hello!", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LooksLikeBase64(tt.s)
			if got != tt.want {
				t.Errorf("LooksLikeBase64(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestFormatOutgoingOCMAddressFromUserID(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		provider string
	}{
		{name: "simple", userID: "alice", provider: "example.org"},
		{name: "uuid with port", userID: "550e8400-e29b-41d4-a716-446655440000", provider: "provider.net:9200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := FormatOutgoingOCMAddressFromUserID(tt.userID, tt.provider)

			identifier, prov, err := Parse(addr)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", addr, err)
			}

			if prov != tt.provider {
				t.Errorf("provider = %q, want %q", prov, tt.provider)
			}

			wantIdentifier := EncodeFederatedOpaqueID(tt.userID, tt.provider)
			if identifier != wantIdentifier {
				t.Errorf("identifier = %q, want %q", identifier, wantIdentifier)
			}

			gotUserID, gotIDP, ok := DecodeFederatedOpaqueID(identifier)
			if !ok {
				t.Fatalf("DecodeFederatedOpaqueID(%q) failed", identifier)
			}
			if gotUserID != tt.userID {
				t.Errorf("round-trip userID = %q, want %q", gotUserID, tt.userID)
			}
			if gotIDP != tt.provider {
				t.Errorf("round-trip idp = %q, want %q", gotIDP, tt.provider)
			}
		})
	}
}
