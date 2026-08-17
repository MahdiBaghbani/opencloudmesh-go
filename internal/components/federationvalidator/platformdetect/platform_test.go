// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package platformdetect

import (
	"net/http"
	"testing"
)

func TestDetect_KnownProviders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		provider string
		want     string
	}{
		{name: "nextcloud_with_version", provider: "Nextcloud 28", want: PlatformNextcloud},
		{name: "nextcloud_prefix", provider: "nextcloud", want: PlatformNextcloud},
		{name: "owncloud", provider: "ownCloud 10", want: PlatformOwncloud},
		{name: "cernbox_substring", provider: "revad-cernbox", want: PlatformCernbox},
		{name: "ocis_exact", provider: "ocis", want: PlatformOCIS},
		{name: "ocis_scale_prefix", provider: "opencloud-infinite-scale", want: PlatformOCIS},
		{name: "opencloud", provider: "opencloud", want: PlatformOpenCloud},
		{name: "opencloud_prefix", provider: "opencloud-server", want: PlatformOpenCloud},
		{name: "reva_unknown", provider: "reva", want: PlatformUnknown},
		{name: "empty_unknown", provider: "", want: PlatformUnknown},
		{name: "whitespace_unknown", provider: "   ", want: PlatformUnknown},
		{name: "unrecognized_unknown", provider: "some-other-product", want: PlatformUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Detect(tc.provider, nil)
			if got != tc.want {
				t.Fatalf("Detect(%q) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

func TestDetect_EmptyProviderIgnoresHeaders(t *testing.T) {
	t.Parallel()

	headers := http.Header{}
	headers.Set("X-Nextcloud-Well-Known", "1")

	got := Detect("", headers)
	if got != PlatformUnknown {
		t.Fatalf("Detect with empty provider and header = %q, want %q", got, PlatformUnknown)
	}
}

func TestDetect_NoEndpointInference(t *testing.T) {
	t.Parallel()

	endpoint := "https://peer.example/remote.php/dav/files/user"
	_ = endpoint

	got := Detect("", nil)
	if got != PlatformUnknown {
		t.Fatalf("Detect with empty provider = %q, want %q", got, PlatformUnknown)
	}
}
