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

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		maxBytes := int64(config.DefaultMaxResponseBytes)

		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		if readErr != nil {
			return fmt.Errorf("receiver returned status %d: %w", resp.StatusCode, readErr)
		}

		if int64(len(respBody)) > maxBytes {
			return fmt.Errorf("receiver returned status %d: response body too large (%d bytes read)", resp.StatusCode, len(respBody))
		}

		return fmt.Errorf("receiver returned status %d (response body %d bytes)", resp.StatusCode, len(respBody))
	}

	return nil
}

func generateSharedSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate shared secret: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
