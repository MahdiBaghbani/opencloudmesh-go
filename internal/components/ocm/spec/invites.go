// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

// InviteAcceptedRequest carries the wire body for POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1#invite-acceptance-response-details
type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// InviteAcceptedResponse carries the wire body returned for an accepted invite.
type InviteAcceptedResponse struct {
	UserID string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email  string `json:"email"`
	Name   string `json:"name"`
}
