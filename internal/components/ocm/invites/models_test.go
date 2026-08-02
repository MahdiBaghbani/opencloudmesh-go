// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
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
			name:      "padded base64url",
			input:     base64.URLEncoding.EncodeToString([]byte("token@example.com")),
			wantToken: "token",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			name:      "unpadded base64url",
			input:     base64.RawURLEncoding.EncodeToString([]byte("token@example.com")),
			wantToken: "token",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			// 0xFB yields '+' in standard base64, so URLEncoding and RawURLEncoding
			// reject the string and the lenient decoder reaches StdEncoding.
			name:      "standard base64 with plus",
			input:     base64.StdEncoding.EncodeToString([]byte("\xfbtoken@example.com")),
			wantToken: "\xfbtoken",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			name:      "multiple @ in token padded base64url",
			input:     base64.URLEncoding.EncodeToString([]byte("user@name@host@example.com")),
			wantToken: "user@name@host",
			wantFQDN:  "example.com",
			wantErr:   false,
		},
		{
			name:      "multiple @ in token unpadded base64url",
			input:     base64.RawURLEncoding.EncodeToString([]byte("user@name@host@example.com")),
			wantToken: "user@name@host",
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
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
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
	tests := []struct {
		name  string
		token string
		fqdn  string
	}{
		{
			name:  "simple token",
			token: "mytoken123",
			fqdn:  "example.com",
		},
		{
			name:  "url-safe alphabet token",
			token: "???",
			fqdn:  "example.co",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := invites.BuildInviteString(tt.token, tt.fqdn)

			if strings.Contains(encoded, "=") {
				t.Errorf("BuildInviteString(%q, %q) = %q contains padding '='", tt.token, tt.fqdn, encoded)
			}

			if strings.ContainsAny(encoded, "+/") {
				t.Errorf("BuildInviteString(%q, %q) = %q contains standard base64 alphabet '+' or '/'", tt.token, tt.fqdn, encoded)
			}

			gotToken, gotFQDN, err := invites.ParseInviteString(encoded)
			if err != nil {
				t.Fatalf("ParseInviteString(%q) error: %v", encoded, err)
			}

			if gotToken != tt.token {
				t.Errorf("token = %q, want %q", gotToken, tt.token)
			}

			if gotFQDN != tt.fqdn {
				t.Errorf("fqdn = %q, want %q", gotFQDN, tt.fqdn)
			}
		})
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

func TestRoundTrip_MultipleAtInToken(t *testing.T) {
	token := "user@name@host"
	fqdn := "example.com"

	inviteString := invites.BuildInviteString(token, fqdn)

	gotToken, gotFQDN, err := invites.ParseInviteString(inviteString)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotToken != token {
		t.Errorf("token = %q, want %q", gotToken, token)
	}

	if gotFQDN != fqdn {
		t.Errorf("fqdn = %q, want %q", gotFQDN, fqdn)
	}
}
