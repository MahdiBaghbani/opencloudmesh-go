// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package address

import (
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		wantID   string
		wantProv string
		wantErr  bool
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
			t.Parallel()

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

// TestParse_IETF_OCMAddressConformance asserts Parse against the OCM Address
// ABNF (https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L140-L154):
// identifier "@" host [ ":" port ], with the
// identifier separated by the last "@", and the provider MUST NOT contain a
// scheme or path.
func TestParse_IETF_OCMAddressConformance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addr     string
		wantID   string
		wantProv string
		wantErr  bool
	}{
		{
			name:     "ABNF user@reg-name",
			addr:     "cloudid@example.com",
			wantID:   "cloudid",
			wantProv: "example.com",
		},
		{
			name:     "ABNF user@reg-name:port",
			addr:     "cloudid@example.com:443",
			wantID:   "cloudid",
			wantProv: "example.com:443",
		},
		{
			name:     "ABNF email local-part with multiple @",
			addr:     "user@mail.example.org@ocm.example.net",
			wantID:   "user@mail.example.org",
			wantProv: "ocm.example.net",
		},
		{
			name:     "ABNF IPv4 host",
			addr:     "alice@192.0.2.10",
			wantID:   "alice",
			wantProv: "192.0.2.10",
		},
		{
			name:     "ABNF IPv4 host:port",
			addr:     "alice@192.0.2.10:9200",
			wantID:   "alice",
			wantProv: "192.0.2.10:9200",
		},
		{
			name:     "ABNF IP-literal provider",
			addr:     "alice@[2001:db8::1]",
			wantID:   "alice",
			wantProv: "[2001:db8::1]",
		},
		{
			name:    "rejects provider with scheme (MUST NOT)",
			addr:    "alice@https://example.com",
			wantErr: true,
		},
		{
			name:    "rejects provider with path (MUST NOT)",
			addr:    "alice@example.com/ocm",
			wantErr: true,
		},
		{
			name:    "rejects missing @ separator",
			addr:    "only-identifier",
			wantErr: true,
		},
		{
			name:    "rejects empty identifier",
			addr:    "@example.com",
			wantErr: true,
		},
		{
			name:    "rejects empty host",
			addr:    "alice@",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			id, prov, err := Parse(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got id=%q prov=%q", tt.addr, id, prov)
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
