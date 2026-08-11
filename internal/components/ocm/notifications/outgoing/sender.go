// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package outgoing posts OCM share lifecycle notifications to remote peers.
package outgoing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// Sender posts share lifecycle notifications through the shared outbound Poster.
type Sender struct {
	poster *outbound.Poster
}

// NewSender wraps an outbound Poster for notification dispatch.
func NewSender(poster *outbound.Poster) *Sender {
	return &Sender{poster: poster}
}

// Notify sends one OCM notification to targetHost. extra is optional opaque JSON.
func (s *Sender) Notify(
	ctx context.Context,
	targetHost string,
	providerID string,
	resourceType string,
	notificationType string,
	extra json.RawMessage,
) error {
	disc, err := s.poster.DiscoverPeer(ctx, targetHost)
	if err != nil {
		return fmt.Errorf("ocm: discover peer for notification: %w", err)
	}

	if !disc.HasCapability(spec.CapabilityNotifications) {
		return notifications.ErrNotificationsNotAdvertised
	}

	reqBody := spec.NotificationRequest{
		NotificationType: notificationType,
		ProviderID:       providerID,
		ResourceType:     resourceType,
		Notification:     extra,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("ocm: encode notification request: %w", err)
	}

	resp, err := s.poster.SendResolved(ctx, outbound.Request{
		TargetHost:   targetHost,
		EndpointPath: "notifications",
		Kind:         outbound.EndpointNotifications,
		Body:         body,
	}, outbound.ResolvedPeer{
		Discovery: disc,
	})
	if err != nil {
		return fmt.Errorf("ocm: post notification: %w", err)
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("notification rejected with status %d: %w", resp.StatusCode, readErr)
	}

	return fmt.Errorf("notification rejected with status %d: %s", resp.StatusCode, string(respBody))
}
