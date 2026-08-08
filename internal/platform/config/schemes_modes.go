// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

// URL scheme, mode, and strict-preset port constants for config loading and validation.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"

	tlsModeOff = "off"

	ssrfModeStrict = "strict"
	ssrfModeOff    = "off"

	defaultStrictHTTPSPort = 9200
	defaultStrictHTTPPort  = 9280
)
