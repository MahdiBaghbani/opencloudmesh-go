package invites_test

import (
	"encoding/base64"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
)

func TestParseInviteString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantToken   string
		wantFQDN    string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid invite",
			input:     base64.StdEncoding.EncodeToString([]byte("abc123@example.com")),
			wantToken: "abc123",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			name:      "valid invite with port",
			input:     base64.StdEncoding.EncodeToString([]byte("token@example.com:8080")),
			wantToken: "token",
			wantFQDN:  "example.com:8080",
			wantErr:   false,
		},
		{
			name:      "token with @ in it",
			input:     base64.StdEncoding.EncodeToString([]byte("user@local@example.com")),
			wantToken: "user@local",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			name:        "invalid base64",
			input:       "not-valid-base64!!!",
			wantErr:     true,
			errContains: "invalid base64",
		},
		{
			name:        "missing @",
			input:       base64.StdEncoding.EncodeToString([]byte("noatsymbol")),
			wantErr:     true,
			errContains: "missing @",
		},
		{
			name:        "empty token",
			input:       base64.StdEncoding.EncodeToString([]byte("@example.com")),
			wantErr:     true,
			errContains: "empty token",
		},
		{
			name:        "empty provider",
			input:       base64.StdEncoding.EncodeToString([]byte("token@")),
			wantErr:     true,
			errContains: "empty provider",
		},
		{
			name:        "provider with scheme",
			input:       base64.StdEncoding.EncodeToString([]byte("token@https://example.com")),
			wantErr:     true,
			errContains: "contains scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, fqdn, err := invites.ParseInviteString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tt.errContains != "" && !containsStr(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
			if fqdn != tt.wantFQDN {
				t.Errorf("fqdn = %q, want %q", fqdn, tt.wantFQDN)
			}
		})
	}
}

func TestBuildInviteString(t *testing.T) {
	token := "mytoken123"
	fqdn := "example.com:9200"

	result := invites.BuildInviteString(token, fqdn)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Errorf("result is not valid base64: %v", err)
	}

	expected := "mytoken123@example.com:9200"
	if string(decoded) != expected {
		t.Errorf("decoded = %q, want %q", string(decoded), expected)
	}
}

func TestRoundTrip(t *testing.T) {
	token := "secure-random-token"
	fqdn := "cloud.example.org"

	inviteString := invites.BuildInviteString(token, fqdn)
	gotToken, gotFQDN, err := invites.ParseInviteString(inviteString)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotToken != token {
		t.Errorf("token = %q, want %q", gotToken, token)
	}
	if gotFQDN != fqdn {
		t.Errorf("fqdn = %q, want %q", gotFQDN, fqdn)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s[1:], substr) || s[:len(substr)] == substr)
}
