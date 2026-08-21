// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func handleExistingIncomingShare(
	ctx context.Context,
	w http.ResponseWriter,
	log *slog.Logger,
	existing *IncomingShare,
	req *spec.NewShareRequest,
	senderHost string,
	resolvedUser *identity.User,
	observe CreateObserver,
) bool {
	if existing == nil {
		return false
	}

	if incomingShareMatchesRequest(existing, req) {
		if observe != nil {
			if err := observe(ctx, existing); err != nil {
				log.Error("incoming share observer failed", "error", err)
				spec.WriteOCMError(w, reason.OCMStatus(reason.StorageError), reason.StorageError)

				return true
			}
		}

		log.Info("duplicate share, idempotent success",
			"provider_id", req.ProviderID,
			"sender", senderHost)
		writeIncomingCreateShareResponse(w, log, resolvedUser.DisplayName)

		return true
	}

	log.Warn("duplicate share with mismatched payload",
		"provider_id", req.ProviderID,
		"sender", senderHost)
	spec.WriteOCMError(w, http.StatusConflict, "SHARE_ALREADY_EXISTS_WITH_DIFFERENT_PAYLOAD")

	return true
}
