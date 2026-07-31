// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// InviteAcceptedPoster posts the invite-accepted protocol call to a remote
// sender. Wired with an outbound.Poster-based adapter at the service layer.
type InviteAcceptedPoster interface {
	PostInviteAccepted(ctx context.Context, targetHost string, body []byte) (*http.Response, error)
}

// AcceptResult carries the decoded invite-accepted response. AlreadyAccepted
// is true when the sender answered 409 INVITE_ALREADY_ACCEPTED with a
// decodable identity body, which is idempotent success on the retry path.
type AcceptResult struct {
	Response        spec.InviteAcceptedResponse
	AlreadyAccepted bool
}

// SendInviteAccepted sends POST /ocm/invite-accepted to the sender with all
// spec-required fields and returns the decoded response, whose userID is the
// canonical remote sender identity persisted for must-invite.
//
// A 200/201 response must carry a non-empty userID (spec L424-425 marks
// userID REQUIRED). A 409 INVITE_ALREADY_ACCEPTED carrying a decodable
// identity body is idempotent success on retry; a bodyless or identity-less
// 409 from a foreign peer is returned as an honest error.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L383-L387
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L808-L823
func SendInviteAccepted(ctx context.Context, poster InviteAcceptedPoster, req spec.InviteAcceptedRequest, targetHost string) (AcceptResult, error) {
	body, err := json.Marshal(req) //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
	if err != nil {
		return AcceptResult{}, fmt.Errorf("failed to encode request: %w", err)
	}

	resp, err := poster.PostInviteAccepted(ctx, targetHost, body)
	if err != nil {
		return AcceptResult{}, err
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var acceptedResp spec.InviteAcceptedResponse
		if err := json.NewDecoder(resp.Body).Decode(&acceptedResp); err != nil {
			return AcceptResult{}, fmt.Errorf("failed to decode invite-accepted response: %w", err)
		}

		if acceptedResp.UserID == "" {
			return AcceptResult{}, fmt.Errorf("invite-accepted response missing userID (status %d)", resp.StatusCode)
		}

		return AcceptResult{Response: acceptedResp}, nil

	case http.StatusConflict:
		// Duplicate invite-accepted: treat as idempotent success only when the
		// sender returned its identity; otherwise the retry cannot recover the
		// sender identity and must surface an honest error.
		var acceptedResp spec.InviteAcceptedResponse
		if err := json.NewDecoder(resp.Body).Decode(&acceptedResp); err != nil {
			return AcceptResult{}, fmt.Errorf("invite-accepted returned 409 without a decodable identity body: %w", err)
		}

		if acceptedResp.UserID == "" {
			return AcceptResult{}, fmt.Errorf("invite-accepted returned 409 with an empty userID")
		}

		return AcceptResult{Response: acceptedResp, AlreadyAccepted: true}, nil

	default:
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return AcceptResult{}, fmt.Errorf("invite-accepted rejected with status %d: %w", resp.StatusCode, readErr)
		}

		return AcceptResult{}, fmt.Errorf("invite-accepted rejected with status %d: %s", resp.StatusCode, string(respBody))
	}
}
