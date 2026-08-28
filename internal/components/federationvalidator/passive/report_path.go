// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import "strings"

// SetExternalBasePath records the optional app prefix used for report path hints.
func (h *Handler) SetExternalBasePath(path string) {
	if h == nil {
		return
	}

	h.externalBasePath = path
}

// joinReportPath prefixes Config.ExternalBasePath the same way fullPathForSpec
// does: trim slashes and skip an empty base so slash-only values do not leak a
// blank segment. Manifest routes, report paths, and retention paths share this
// helper so they cannot diverge.
func joinReportPath(externalBasePath string, parts ...string) string {
	segments := make([]string, 0, len(parts)+1)

	if trimmed := strings.Trim(externalBasePath, "/"); trimmed != "" {
		segments = append(segments, trimmed)
	}

	for _, part := range parts {
		trimmed := strings.Trim(part, "/")
		if trimmed == "" {
			continue
		}

		segments = append(segments, trimmed)
	}

	if len(segments) == 0 {
		return "/"
	}

	return "/" + strings.Join(segments, "/")
}
