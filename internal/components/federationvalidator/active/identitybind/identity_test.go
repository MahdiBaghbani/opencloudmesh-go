// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identitybind

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

const testUUID = "550e8400-e29b-41d4-a716-446655440000"

func TestCanonicalize(t *testing.T) {
	t.Parallel()

	opaqueAlice := address.EncodeFederatedOpaqueID("alice", "idp.example")
	opaquePort := address.EncodeFederatedOpaqueID("bob", "provider.net:443")
	opaqueKeptPort := address.EncodeFederatedOpaqueID("carol", "provider.net:9200")

	tests := []struct {
		name    string
		raw     string
		scheme  string
		want    Identity
		wantErr bool
	}{
		{
			name:   "ordinary local address",
			raw:    "malek@o.com",
			scheme: "https",
			want:   Identity{LocalUser: "malek", Provider: "o.com"},
		},
		{
			name:   "https default port stripped",
			raw:    "malek@o.com:443",
			scheme: "https",
			want:   Identity{LocalUser: "malek", Provider: "o.com"},
		},
		{
			name:   "http default port stripped",
			raw:    "malek@o.com:80",
			scheme: "http",
			want:   Identity{LocalUser: "malek", Provider: "o.com"},
		},
		{
			name:   "non-default port preserved",
			raw:    "malek@o.com:8443",
			scheme: "https",
			want:   Identity{LocalUser: "malek", Provider: "o.com:8443"},
		},
		{
			name:   "http does not strip 443",
			raw:    "malek@o.com:443",
			scheme: "http",
			want:   Identity{LocalUser: "malek", Provider: "o.com:443"},
		},
		{
			name:   "uppercase host lowercased",
			raw:    "malek@O.COM",
			scheme: "https",
			want:   Identity{LocalUser: "malek", Provider: "o.com"},
		},
		{
			name:   "opaque identifier then outer provider",
			raw:    opaqueAlice + "@idp.example",
			scheme: "https",
			want: Identity{
				LocalUser: "alice",
				Provider:  "idp.example",
				Opaque:    true,
			},
		},
		{
			name:   "bare opaque payload",
			raw:    opaqueAlice,
			scheme: "https",
			want: Identity{
				LocalUser: "alice",
				Provider:  "idp.example",
				Opaque:    true,
			},
		},
		{
			name:   "opaque decoded idp default port stripped",
			raw:    opaquePort + "@provider.net",
			scheme: "https",
			want: Identity{
				LocalUser: "bob",
				Provider:  "provider.net",
				Opaque:    true,
			},
		},
		{
			name:   "opaque decoded idp non-default port kept",
			raw:    opaqueKeptPort + "@provider.net:9200",
			scheme: "https",
			want: Identity{
				LocalUser: "carol",
				Provider:  "provider.net:9200",
				Opaque:    true,
			},
		},
		{
			name:   "uuid local user stays unenforceable shape",
			raw:    testUUID + "@o.com",
			scheme: "https",
			want:   Identity{LocalUser: testUUID, Provider: "o.com"},
		},
		{
			name:    "empty rejected",
			raw:     "",
			scheme:  "https",
			wantErr: true,
		},
		{
			name:    "missing at rejected",
			raw:     "noleft",
			scheme:  "https",
			wantErr: true,
		},
		{
			name:    "scheme in provider rejected",
			raw:     "user@https://o.com",
			scheme:  "https",
			wantErr: true,
		},
		{
			name:    "path in provider rejected",
			raw:     "user@o.com/ocm",
			scheme:  "https",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Canonicalize(tt.raw, tt.scheme)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Canonicalize(%q, %q) error = nil, want error", tt.raw, tt.scheme)
				}

				return
			}

			if err != nil {
				t.Fatalf("Canonicalize(%q, %q) unexpected error: %v", tt.raw, tt.scheme, err)
			}

			if got != tt.want {
				t.Fatalf("Canonicalize(%q, %q) = %+v, want %+v", tt.raw, tt.scheme, got, tt.want)
			}
		})
	}
}

func TestIsPlainLocalUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		user string
		want bool
	}{
		{name: "plain username", user: "malek", want: true},
		{name: "plain other user", user: "omar", want: true},
		{name: "empty is not plain", user: "", want: false},
		{name: "uuid is not plain", user: testUUID, want: false},
		{name: "uppercase uuid is not plain", user: strings.ToUpper(testUUID), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsPlainLocalUser(tt.user); got != tt.want {
				t.Fatalf("IsPlainLocalUser(%q) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	malek := mustCanonicalize(t, "malek@o.com")
	omar := mustCanonicalize(t, "omar@o.com")
	malekPort := mustCanonicalize(t, "malek@o.com:443")
	malekOtherHost := mustCanonicalize(t, "malek@other.example")
	opaqueOmar := mustCanonicalize(t, address.EncodeFederatedOpaqueID("omar", "o.com")+"@o.com")
	uuidUser := mustCanonicalize(t, testUUID+"@o.com")

	tests := []struct {
		name  string
		left  Identity
		right Identity
		want  Comparison
	}{
		{
			name:  "plain match",
			left:  malek,
			right: malekPort,
			want: Comparison{
				HostsEqual:      true,
				UsersEqual:      true,
				UserEnforceable: true,
			},
		},
		{
			name:  "plain user mismatch same host",
			left:  malek,
			right: omar,
			want: Comparison{
				HostsEqual:      true,
				UsersEqual:      false,
				UserEnforceable: true,
			},
		},
		{
			name:  "plain host mismatch",
			left:  malek,
			right: malekOtherHost,
			want: Comparison{
				HostsEqual:      false,
				UsersEqual:      true,
				UserEnforceable: true,
			},
		},
		{
			name:  "opaque mismatch is unenforceable",
			left:  malek,
			right: opaqueOmar,
			want: Comparison{
				HostsEqual:      true,
				UsersEqual:      false,
				UserEnforceable: false,
			},
		},
		{
			name:  "uuid user is unenforceable",
			left:  malek,
			right: uuidUser,
			want: Comparison{
				HostsEqual:      true,
				UsersEqual:      false,
				UserEnforceable: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Compare(tt.left, tt.right)
			if got != tt.want {
				t.Fatalf("Compare(%+v, %+v) = %+v, want %+v", tt.left, tt.right, got, tt.want)
			}
		})
	}
}

func TestCanonicalize_OrdinaryPlainNamesAreNotOpaque(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"malek@o.com", "omar@o.com", "accepter-user@peer.example"} {
		got, err := Canonicalize(raw, "https")
		if err != nil {
			t.Fatalf("Canonicalize(%q) unexpected error: %v", raw, err)
		}

		if got.Opaque {
			t.Fatalf("Canonicalize(%q).Opaque = true, want false", raw)
		}

		if !IsPlainLocalUser(got.LocalUser) {
			t.Fatalf("Canonicalize(%q) local user %q should be plain", raw, got.LocalUser)
		}
	}
}

func mustCanonicalize(t *testing.T, raw string) Identity {
	t.Helper()

	got, err := Canonicalize(raw, "https")
	if err != nil {
		t.Fatalf("Canonicalize(%q): %v", raw, err)
	}

	return got
}
