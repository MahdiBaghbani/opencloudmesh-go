// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"encoding/json"
)

// Notifier sends share lifecycle notifications to remote senders after local
// inbox actions. The concrete implementation lives in notifications/outgoing.
type Notifier interface {
	Notify(
		ctx context.Context,
		targetHost string,
		providerID string,
		resourceType string,
		notificationType string,
		extra json.RawMessage,
	) error
}
