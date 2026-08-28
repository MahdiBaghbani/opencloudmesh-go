// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// ObserveNotification is the post-success hook on POST /ocm/notifications
// for an outgoing-share lifecycle update. It records the inbound transcript
// and the explicit notification-area evidence when the notification names
// the active run's dispatched share.
func (s *Service) ObserveNotification(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	if share == nil {
		return nil
	}

	runID, err := s.deps.Store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: find active run: %w", err)
	}

	reservation, err := s.deps.Store.GetDispatchReservation(ctx, runID)
	if errors.Is(err, validatorcore.ErrDispatchReservationNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: load dispatch reservation: %w", err)
	}

	if reservation.ProviderID != share.ProviderID {
		return nil
	}

	if err := s.deps.Store.PersistActiveExchangeAndFact(
		ctx,
		validatorcore.IncomingNotificationExchange(runID),
		validatorcore.NotificationReceivedFact(runID, nil),
	); err != nil {
		return fmt.Errorf("reverseshare: record notification: %w", err)
	}

	return nil
}
