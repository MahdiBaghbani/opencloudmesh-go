// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package address

import "testing"

func TestNormalizedProviderFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		addr        string
		scheme      string
		expected    string
		expectError bool
	}{
		{"simple address", "user@example.com", "https", "example.com", false},
		{"with port", "user@example.com:9200", "https", "example.com:9200", false},
		{"uppercase host", "user@EXAMPLE.COM", "https", "example.com", false},
		{"default port stripped", "user@example.com:443", "https", "example.com", false},
		{"no @ separator", "invalid", "https", "", true},
		{"empty string", "", "https", "", true},
		{"email identifier (last-@)", "alice@university.edu@provider.net", "https", "provider.net", false},
		{"email identifier with port (last-@)", "alice@uni.edu@provider.net:443", "https", "provider.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := NormalizedProviderFrom(tt.addr, tt.scheme)
			if tt.expectError {
				if err == nil {
					t.Errorf("NormalizedProviderFrom(%q) expected error, got %q", tt.addr, result)
				}

				return
			}

			if err != nil {
				t.Fatalf("NormalizedProviderFrom(%q) unexpected error: %v", tt.addr, err)
			}

			if result != tt.expected {
				t.Errorf("NormalizedProviderFrom(%q) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}
