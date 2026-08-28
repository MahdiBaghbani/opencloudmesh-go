// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package platformdetect

import (
	"net/http"
	"strings"
)

const (
	// PlatformUnknown is the detection result when the provider is empty or unrecognized.
	PlatformUnknown = "unknown"
	// PlatformNextcloud is the Nextcloud EFSS label.
	PlatformNextcloud = "nextcloud"
	// PlatformOwncloud is the ownCloud EFSS label.
	PlatformOwncloud = "owncloud"
	// PlatformCernbox is the CERNBox EFSS label.
	PlatformCernbox = "cernbox"
	// PlatformOCIS is the oCIS EFSS label.
	PlatformOCIS = "ocis"
	// PlatformOpenCloud is the OpenCloud EFSS label.
	PlatformOpenCloud = "opencloud"
)

// Detect maps a discovery provider string to a locked EFSS platform label.
// Empty or whitespace-only providers always return PlatformUnknown.
// Response headers and endpoint paths are never used for inference.
func Detect(provider string, headers http.Header) string {
	_ = headers

	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		return PlatformUnknown
	}

	if normalized == "reva" {
		return PlatformUnknown
	}

	if strings.HasPrefix(normalized, PlatformNextcloud) {
		return PlatformNextcloud
	}

	if strings.HasPrefix(normalized, PlatformOwncloud) {
		return PlatformOwncloud
	}

	if strings.Contains(normalized, PlatformCernbox) {
		return PlatformCernbox
	}

	if normalized == PlatformOCIS || strings.HasPrefix(normalized, "opencloud-infinite-scale") {
		return PlatformOCIS
	}

	if strings.HasPrefix(normalized, PlatformOpenCloud) {
		return PlatformOpenCloud
	}

	return PlatformUnknown
}
