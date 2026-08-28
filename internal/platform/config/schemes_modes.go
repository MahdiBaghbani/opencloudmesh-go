// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

// URL scheme, mode, and strict-preset port constants for config loading and validation.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"

	// TLSModeOff disables in-process TLS; the HTTP server listens in plain HTTP.
	TLSModeOff = "off"
	// TLSModeTerminated terminates TLS upstream; forwarded headers from trusted proxies carry scheme.
	TLSModeTerminated = "terminated"

	tlsModeOff        = TLSModeOff
	tlsModeTerminated = TLSModeTerminated

	ssrfModeStrict = "strict"
	ssrfModeOff    = "off"

	defaultStrictHTTPSPort = 9200
	defaultStrictHTTPPort  = 9280
)
