// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package client provides a safe outbound HTTP client with SSRF protections.
// See client.go for the concrete implementation.

package client

import (
	"context"
	"net/http"
)

// HTTPClient is the shared interface for outbound HTTP requests.
// Implemented by ContextClient; used by outgoing share/invite handlers and
// inbox invite handlers to avoid per-package interface duplication.
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}
