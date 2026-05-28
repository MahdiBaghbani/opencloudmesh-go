// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package harness

import "testing"

func TestHealthEndpointURL(t *testing.T) {
	cases := []struct {
		name             string
		baseURL          string
		externalBasePath string
		want             string
	}{
		{
			name:             "no base path mounts at root",
			baseURL:          "http://localhost:8080",
			externalBasePath: "",
			want:             "http://localhost:8080/api/healthz",
		},
		{
			name:             "leading-slash base path",
			baseURL:          "http://localhost:8080",
			externalBasePath: "/ocm",
			want:             "http://localhost:8080/ocm/api/healthz",
		},
		{
			name:             "base path without leading slash",
			baseURL:          "https://localhost:8443",
			externalBasePath: "ocm",
			want:             "https://localhost:8443/ocm/api/healthz",
		},
		{
			name:             "trailing slashes trimmed on both",
			baseURL:          "http://localhost:8080/",
			externalBasePath: "/ocm/",
			want:             "http://localhost:8080/ocm/api/healthz",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := healthEndpointURL(tc.baseURL, tc.externalBasePath)
			if got != tc.want {
				t.Fatalf("healthEndpointURL(%q, %q) = %q, want %q",
					tc.baseURL, tc.externalBasePath, got, tc.want)
			}
		})
	}
}
