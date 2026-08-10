// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// HandleExistingIncomingShareForTest exercises duplicate create-share handling.
func HandleExistingIncomingShareForTest(
	w http.ResponseWriter,
	log *slog.Logger,
	existing *IncomingShare,
	req *spec.NewShareRequest,
	senderHost string,
	resolvedUser *identity.User,
) bool {
	return handleExistingIncomingShare(w, log, existing, req, senderHost, resolvedUser)
}
