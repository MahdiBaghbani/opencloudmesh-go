// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// incomingShareMatchesRequest reports whether stored material fields match the
// incoming share request. Nil req.Protocol.WebDAV is treated as empty WebDAV
// material. Permissions and requirements use ordered slice comparison.
func incomingShareMatchesRequest(existing *IncomingShare, req *spec.NewShareRequest) bool {
	if existing == nil || req == nil {
		return false
	}

	webdavURI, webdavSharedSecret, webdavPermissions, webdavRequirements := extractWebDAV(req)

	if !incomingShareIdentityFieldsMatch(existing, req) {
		return false
	}

	return incomingShareWebDAVMaterialMatch(
		existing,
		webdavURI,
		webdavSharedSecret,
		webdavPermissions,
		webdavRequirements,
	)
}

func incomingShareIdentityFieldsMatch(existing *IncomingShare, req *spec.NewShareRequest) bool {
	return existing.Name == req.Name &&
		existing.ResourceType == req.ResourceType &&
		existing.ShareWith == req.ShareWith &&
		existing.ShareType == req.ShareType &&
		existing.Owner == req.Owner &&
		existing.Sender == req.Sender &&
		existing.ProtocolName == req.Protocol.Name &&
		existing.Description == req.Description &&
		int64PtrEqual(existing.Expiration, req.Expiration)
}

func incomingShareWebDAVMaterialMatch(
	existing *IncomingShare,
	webdavURI, webdavSharedSecret string,
	webdavPermissions, webdavRequirements []string,
) bool {
	return existing.WebDAVID == webdavURI &&
		existing.SharedSecret == webdavSharedSecret &&
		orderedStringSlicesEqual(existing.Permissions, webdavPermissions) &&
		orderedStringSlicesEqual(existing.Requirements, webdavRequirements)
}

// extractWebDAV returns WebDAV material from req with copied permissions and
// requirements slices so storage and comparison behave symmetrically. Nil req
// or nil req.Protocol.WebDAV yields empty material.
func extractWebDAV(req *spec.NewShareRequest) (uri, sharedSecret string, permissions, requirements []string) {
	if req == nil {
		return "", "", nil, nil
	}

	webdav := req.Protocol.WebDAV
	if webdav == nil {
		return "", "", nil, nil
	}

	return webdav.URI, webdav.SharedSecret, append([]string(nil), webdav.Permissions...), append([]string(nil), webdav.Requirements...)
}

func orderedStringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func int64PtrEqual(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return *a == *b
}
