// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package localidentity_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func TestValidateExternalBasePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"root path", "/ocm", "/ocm", false},
		{"nested path", "/apps/ocm", "/apps/ocm", false},
		{"whitespace", " /ocm", "", true},
		{"missing leading slash", "ocm", "", true},
		{"trailing slash", "/ocm/", "", true},
		{"dot", "/ocm/../x", "", true},
		{"empty segment", "/ocm//x", "", true},
		{"backslash at position 2", "/\\evil", "", true},
		{"backslash mid path", "/ocm\\evil", "", true},
		{"leading double slash", "//evil", "", true},
		{"parent segment only", "..", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := localidentity.ValidateExternalBasePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDerive_ProviderDomainStripsDefaultPorts(t *testing.T) {
	tests := []struct {
		name         string
		publicOrigin string
		wantProvider string
		wantCompare  string
		wantOrigin   string
		wantEndpoint string
		externalBase string
	}{
		{
			name:         "https default port stripped",
			publicOrigin: "https://a.com:443",
			wantProvider: "a.com",
			wantCompare:  "a.com",
			wantOrigin:   "https://a.com:443",
			wantEndpoint: "https://a.com:443",
		},
		{
			name:         "http default port stripped",
			publicOrigin: "http://a.com:80",
			wantProvider: "a.com",
			wantCompare:  "a.com",
			wantOrigin:   "http://a.com:80",
			wantEndpoint: "http://a.com:80",
		},
		{
			name:         "non-default port preserved",
			publicOrigin: "https://a.com:9200",
			wantProvider: "a.com:9200",
			wantCompare:  "a.com:9200",
			wantOrigin:   "https://a.com:9200",
			wantEndpoint: "https://a.com:9200",
		},
		{
			name:         "with external base path",
			publicOrigin: "https://cloud.example.com",
			externalBase: "/ocm",
			wantProvider: "cloud.example.com",
			wantCompare:  "cloud.example.com",
			wantOrigin:   "https://cloud.example.com",
			wantEndpoint: "https://cloud.example.com/ocm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := localidentity.Derive(tt.publicOrigin, tt.externalBase)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}

			if id.ProviderDomain != tt.wantProvider {
				t.Errorf("ProviderDomain = %q, want %q", id.ProviderDomain, tt.wantProvider)
			}

			if id.ProviderDomainCompare != tt.wantCompare {
				t.Errorf("ProviderDomainCompare = %q, want %q", id.ProviderDomainCompare, tt.wantCompare)
			}

			if id.Origin != tt.wantOrigin {
				t.Errorf("Origin = %q, want %q", id.Origin, tt.wantOrigin)
			}

			if id.EndpointBase != tt.wantEndpoint {
				t.Errorf("EndpointBase = %q, want %q", id.EndpointBase, tt.wantEndpoint)
			}

			if id.ExternalBasePath != tt.externalBase {
				t.Errorf("ExternalBasePath = %q, want %q", id.ExternalBasePath, tt.externalBase)
			}
		})
	}
}

func TestDerive_SchemeFromOrigin(t *testing.T) {
	id, err := localidentity.Derive("http://localhost:8080", "")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	if id.Scheme != "http" {
		t.Errorf("Scheme = %q, want http", id.Scheme)
	}
}

func TestDerive_EmptyPublicOrigin(t *testing.T) {
	_, err := localidentity.Derive("", "/ocm")
	if err == nil {
		t.Fatal("expected error for empty public_origin")
	}
}

func TestDerive_InvalidExternalBasePath(t *testing.T) {
	_, err := localidentity.Derive("https://example.com", "ocm")
	if err == nil {
		t.Fatal("expected error for invalid external base path")
	}
}
