// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invite

import (
	"fmt"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	tsession "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/session"
)

// OutgoingCreateResponse mirrors POST /api/invites/outgoing.
type OutgoingCreateResponse struct {
	InviteString string `json:"inviteString"`
	Token        string `json:"token"`
	ProviderFQDN string `json:"providerFqdn"`
}

// ImportResponse mirrors POST /api/inbox/invites/import.
type ImportResponse struct {
	ID         string               `json:"id"`
	SenderFQDN string               `json:"senderFqdn"`
	Status     invites.InviteStatus `json:"status"`
}

// InboxListResponse mirrors GET /api/inbox/invites.
type InboxListResponse struct {
	Invites []InboxInviteView `json:"invites"`
}

// InboxInviteView is one inbox invite row from the list API.
type InboxInviteView struct {
	ID         string               `json:"id"`
	SenderFQDN string               `json:"senderFqdn"`
	Status     invites.InviteStatus `json:"status"`
}

// AcceptResponse mirrors POST /api/inbox/invites/{id}/accept.
type AcceptResponse struct {
	Status   invites.InviteStatus `json:"status"`
	InviteID string               `json:"inviteId"`
}

// CreateOutgoing posts to /api/invites/outgoing and returns the created invite.
func CreateOutgoing(client *http.Client, baseURL, token string) (*OutgoingCreateResponse, int, error) {
	req, err := tsession.NewRequest(http.MethodPost, baseURL, "/api/invites/outgoing", token, map[string]any{})
	if err != nil {
		return nil, 0, err
	}

	var resp OutgoingCreateResponse

	status, raw, err := tsession.DoJSON(client, req, &resp)
	if err != nil {
		return nil, status, err
	}

	if status != http.StatusCreated {
		return nil, status, fmt.Errorf("create outgoing invite: status=%d body=%s", status, raw)
	}

	if resp.InviteString == "" || resp.Token == "" {
		return nil, status, fmt.Errorf("create outgoing invite returned empty token or inviteString: %s", raw)
	}

	return &resp, status, nil
}

// Import posts to /api/inbox/invites/import.
func Import(client *http.Client, baseURL, token, inviteString string) (*ImportResponse, int, error) {
	req, err := tsession.NewRequest(http.MethodPost, baseURL, "/api/inbox/invites/import", token, map[string]string{
		"inviteString": inviteString,
	})
	if err != nil {
		return nil, 0, err
	}

	var resp ImportResponse

	status, raw, err := tsession.DoJSON(client, req, &resp)
	if err != nil {
		return nil, status, err
	}

	if status != http.StatusCreated && status != http.StatusOK {
		return nil, status, fmt.Errorf("import invite: status=%d body=%s", status, raw)
	}

	if resp.ID == "" {
		return nil, status, fmt.Errorf("import invite returned empty id: %s", raw)
	}

	return &resp, status, nil
}

// Accept posts to /api/inbox/invites/{id}/accept.
func Accept(client *http.Client, baseURL, token, inviteID string) (*AcceptResponse, int, error) {
	path := fmt.Sprintf("/api/inbox/invites/%s/accept", inviteID)

	req, err := tsession.NewRequest(http.MethodPost, baseURL, path, token, nil)
	if err != nil {
		return nil, 0, err
	}

	var resp AcceptResponse

	status, raw, err := tsession.DoJSON(client, req, &resp)
	if err != nil {
		return nil, status, err
	}

	if status != http.StatusOK {
		return nil, status, fmt.Errorf("accept invite: status=%d body=%s", status, raw)
	}

	if resp.Status != invites.InviteStatusAccepted {
		return nil, status, fmt.Errorf("accept invite status=%q, want accepted", resp.Status)
	}

	return &resp, status, nil
}

// ListInbox returns GET /api/inbox/invites.
func ListInbox(client *http.Client, baseURL, token string) (*InboxListResponse, int, error) {
	req, err := tsession.NewRequest(http.MethodGet, baseURL, "/api/inbox/invites", token, nil)
	if err != nil {
		return nil, 0, err
	}

	var resp InboxListResponse

	status, raw, err := tsession.DoJSON(client, req, &resp)
	if err != nil {
		return nil, status, err
	}

	if status != http.StatusOK {
		return nil, status, fmt.Errorf("list inbox invites: status=%d body=%s", status, raw)
	}

	return &resp, status, nil
}

// FindInboxInvite returns the invite with the given id from a list response.
func FindInboxInvite(list *InboxListResponse, inviteID string) (*InboxInviteView, error) {
	if list == nil {
		return nil, fmt.Errorf("nil inbox list")
	}

	for i := range list.Invites {
		if list.Invites[i].ID == inviteID {
			return &list.Invites[i], nil
		}
	}

	return nil, fmt.Errorf("invite %q not found in inbox list", inviteID)
}
