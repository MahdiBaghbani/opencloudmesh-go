// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
)

// TestValidateLocalJwksURIOverride confirms the local override validation
// helper enforces the same transport, credential, fragment, and
// same-authority policy as peer jwksUri validation.
func TestValidateLocalJwksURIOverride(t *testing.T) {
	const httpsOrigin = "https://cloud.example.com"

	tests := []struct {
		name    string
		jwksURI string
		origin  string
		wantErr string
	}{
		{
			name:    "empty override is allowed",
			jwksURI: "",
			origin:  httpsOrigin,
		},
		{
			name:    "same-authority override on origin",
			jwksURI: "https://cloud.example.com/custom/jwks.json",
			origin:  httpsOrigin,
		},
		{
			name:    "cross-authority override rejected",
			jwksURI: "https://other.example.com/jwks.json",
			origin:  httpsOrigin,
			wantErr: "authority",
		},
		{
			name:    "http rejected with https origin",
			jwksURI: "http://cloud.example.com/jwks.json",
			origin:  httpsOrigin,
			wantErr: "must use https",
		},
		{
			name:    "http allowed with explicit development http origin",
			jwksURI: "http://cloud.example.com:9200/jwks.json",
			origin:  "http://cloud.example.com:9200",
		},
		{
			name:    "credentials rejected",
			jwksURI: "https://user:pass@cloud.example.com/jwks.json",
			origin:  httpsOrigin,
			wantErr: "credentials",
		},
		{
			name:    "fragment rejected",
			jwksURI: "https://cloud.example.com/jwks.json#key-1",
			origin:  httpsOrigin,
			wantErr: "fragment",
		},
		{
			name:    "bare fragment delimiter rejected",
			jwksURI: "https://cloud.example.com/jwks.json#",
			origin:  httpsOrigin,
			wantErr: "fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := discovery.ValidateLocalJwksURIOverride(tt.jwksURI, tt.origin)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateLocalJwksURIOverride(%q, %q) error = %v, want nil", tt.jwksURI, tt.origin, err)
				}

				return
			}

			if err == nil {
				t.Fatalf("ValidateLocalJwksURIOverride(%q, %q) error = nil, want %q", tt.jwksURI, tt.origin, tt.wantErr)
			}

			msg := err.Error()
			if !strings.Contains(msg, tt.wantErr) {
				t.Fatalf("ValidateLocalJwksURIOverride(%q, %q) error = %q, want substring %q", tt.jwksURI, tt.origin, err, tt.wantErr)
			}

			if strings.Contains(tt.jwksURI, "user:pass") {
				if strings.Contains(msg, "user:pass") || strings.Contains(msg, "user@") {
					t.Fatalf("ValidateLocalJwksURIOverride error = %q, must not echo credential userinfo", msg)
				}
			}
		})
	}
}
