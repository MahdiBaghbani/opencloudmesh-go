// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"context"
	"fmt"
	"net/http"

	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
)

// inviteAcceptedPoster adapts outbound.Poster to the invites/incoming
// InviteAcceptedPoster domain port, fixing the invites endpoint kind and the
// invite-accepted endpoint path.
type inviteAcceptedPoster struct {
	poster *outbound.Poster
}

var _ invitesincoming.InviteAcceptedPoster = (*inviteAcceptedPoster)(nil)

// NewInviteAcceptedPoster wires an outbound.Poster as the invite-accepted
// domain poster.
func NewInviteAcceptedPoster(poster *outbound.Poster) invitesincoming.InviteAcceptedPoster {
	return &inviteAcceptedPoster{poster: poster}
}

// PostInviteAccepted posts the invite-accepted protocol call to the sender.
func (a *inviteAcceptedPoster) PostInviteAccepted(ctx context.Context, targetHost string, body []byte) (*http.Response, error) {
	resp, err := a.poster.Send(ctx, outbound.Request{
		TargetHost:   targetHost,
		EndpointPath: "invite-accepted",
		Kind:         outbound.EndpointInvites,
		Body:         body,
	})
	if err != nil {
		return resp, fmt.Errorf("services: post accepted invite: %w", err)
	}

	return resp, nil
}
