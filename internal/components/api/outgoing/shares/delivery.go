// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// ReceiverStatusError is a receiver response that is not an accepted
// success (HTTP 200 or 201). Callers inspect it with errors.As. Unwrap
// exposes a read or size cause when the body could not be captured
// cleanly.
type ReceiverStatusError struct {
	Status int
	Body   []byte
	err    error
}

func (e *ReceiverStatusError) Error() string {
	if e == nil {
		return "receiver status error"
	}

	if e.err != nil {
		return fmt.Sprintf("receiver returned status %d: %v", e.Status, e.err)
	}

	return fmt.Sprintf("receiver returned status %d (response body %d bytes)", e.Status, len(e.Body))
}

func (e *ReceiverStatusError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.err
}

// PermanentRefuse reports receiver HTTP 400 and 403, the only permanent
// dispatch hard failures. Every other receiver status is retryable.
func (e *ReceiverStatusError) PermanentRefuse() bool {
	if e == nil {
		return false
	}

	return e.Status == http.StatusBadRequest || e.Status == http.StatusForbidden
}

type resolvedPeerOrigin struct {
	baseURL    string
	peerDomain string
}

func (h *Handler) resolvePeerOrigin(peerDomain string) resolvedPeerOrigin {
	if h.peerOrigin == nil {
		return resolvedPeerOrigin{}
	}

	decision := h.peerOrigin.Resolve(peerDomain)

	return resolvedPeerOrigin{
		baseURL:    decision.BaseURL,
		peerDomain: decision.PeerDomain,
	}
}

func (h *Handler) sendShareToReceiver(
	ctx context.Context,
	origin resolvedPeerOrigin,
	disc *spec.Discovery,
	payload spec.NewShareRequest,
) error {
	body, err := json.Marshal(payload) //nolint:errchkjson // payload type cannot fail to encode, so the checked error is always nil
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	poster := outbound.NewPoster(h.httpClient, h.discoveryClient, h.signer, h.peerOrigin)

	resp, err := poster.SendResolved(ctx, outbound.Request{
		TargetHost:   origin.peerDomain,
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         body,
	}, outbound.ResolvedPeer{
		Discovery: disc,
	})
	if err != nil {
		return fmt.Errorf("api: send outgoing share: %w", err)
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	default:
		return readReceiverStatusError(resp)
	}
}

func readReceiverStatusError(resp *http.Response) error {
	maxBytes := int64(config.DefaultMaxResponseBytes)

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if readErr != nil {
		return &ReceiverStatusError{
			Status: resp.StatusCode,
			err:    readErr,
		}
	}

	if int64(len(respBody)) > maxBytes {
		return &ReceiverStatusError{
			Status: resp.StatusCode,
			Body:   respBody[:maxBytes],
			err:    fmt.Errorf("response body too large (%d bytes read)", len(respBody)),
		}
	}

	return &ReceiverStatusError{
		Status: resp.StatusCode,
		Body:   respBody,
	}
}

func generateSharedSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate shared secret: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
