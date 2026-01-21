package crypto

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// PeerResolver extracts declared peer identity from OCM request bodies.
type PeerResolver struct{}

// NewPeerResolver creates a new peer resolver.
func NewPeerResolver() *PeerResolver {
	return &PeerResolver{}
}

// ocmAddress parses an OCM address (user@host or user@host:port).
func parseOCMAddress(addr string) (user, host string, err error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty OCM address")
	}

	parts := strings.SplitN(addr, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid OCM address format: %s", addr)
	}

	return parts[0], parts[1], nil
}

// ResolveSharesRequest extracts the peer from POST /ocm/shares request body.
// The peer is derived from the sender or owner field.
func (p *PeerResolver) ResolveSharesRequest(r *http.Request, body []byte) (string, error) {
	var req struct {
		Sender string `json:"sender"`
		Owner  string `json:"owner"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse shares request: %w", err)
	}

	// Try sender first, then owner
	addr := req.Sender
	if addr == "" {
		addr = req.Owner
	}

	if addr == "" {
		return "", fmt.Errorf("no sender or owner in shares request")
	}

	_, host, err := parseOCMAddress(addr)
	if err != nil {
		return "", err
	}

	return host, nil
}

// ResolveNotificationsRequest extracts the peer from POST /ocm/notifications.
// The request body has no sender fields, so we use providerId lookup or signature.
// This resolver returns an empty string to indicate signature-based resolution is needed.
func (p *PeerResolver) ResolveNotificationsRequest(r *http.Request, body []byte) (string, error) {
	// Notifications have no explicit sender field.
	// Peer identity must come from:
	// 1. Valid signature keyId (handled by middleware)
	// 2. ProviderId lookup to exactly one stored share (handled by share repository)
	//
	// Return empty to signal the middleware should use signature-based resolution.
	return "", nil
}

// ResolveInviteAcceptedRequest extracts the peer from POST /ocm/invite-accepted.
// The peer is the recipientProvider field (FQDN).
func (p *PeerResolver) ResolveInviteAcceptedRequest(r *http.Request, body []byte) (string, error) {
	var req struct {
		RecipientProvider string `json:"recipientProvider"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse invite-accepted request: %w", err)
	}

	if req.RecipientProvider == "" {
		return "", fmt.Errorf("no recipientProvider in invite-accepted request")
	}

	// recipientProvider is already a host (FQDN), not an OCM address
	return req.RecipientProvider, nil
}

// ResolveTokenRequest extracts the peer from POST /ocm/token.
// The peer must be derived from the signed request.
func (p *PeerResolver) ResolveTokenRequest(r *http.Request, body []byte) (string, error) {
	// Token exchange requires signature-based authentication
	return "", nil
}
