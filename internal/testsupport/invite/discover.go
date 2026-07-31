// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invite

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// DiscoverResponse mirrors GET /ocm-aux/discover success payload fields used by tests.
type DiscoverResponse struct {
	Success                    bool            `json:"success"`
	Error                      string          `json:"error,omitempty"`
	ReasonCode                 string          `json:"reasonCode,omitempty"`
	Discovery                  *spec.Discovery `json:"discovery,omitempty"`
	InviteAcceptDialogAbsolute string          `json:"inviteAcceptDialogAbsolute,omitempty"`
}

// DiscoverProvider calls GET /ocm-aux/discover?base=<providerBaseURL>.
func DiscoverProvider(client *http.Client, auxBaseURL, providerBaseURL string) (*DiscoverResponse, int, error) {
	if client == nil {
		client = http.DefaultClient
	}

	discoverURL := auxBaseURL + "/ocm-aux/discover?base=" + url.QueryEscape(providerBaseURL)

	resp, err := client.Get(discoverURL)
	if err != nil {
		return nil, 0, fmt.Errorf("GET discover: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort body cleanup; close error is not actionable on an abandoned response

	var body DiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode discover response: %w", err)
	}

	return &body, resp.StatusCode, nil
}

// BuildWAYFRedirectURL matches internal/components/ui/templates/wayf.html redirectToProvider.
func BuildWAYFRedirectURL(inviteAcceptDialog, token, providerDomain string) string {
	sep := "?"
	if strings.Contains(inviteAcceptDialog, "?") {
		sep = "&"
	}

	return inviteAcceptDialog + sep +
		"token=" + url.QueryEscape(token) +
		"&providerDomain=" + url.QueryEscape(providerDomain)
}
