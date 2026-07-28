// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outbound

// EndpointKind classifies outbound OCM POST targets for signing policy.
type EndpointKind string

const (
	// EndpointShares is the shares outbound endpoint kind.
	EndpointShares EndpointKind = "shares"
	// EndpointInvites is the invites outbound endpoint kind.
	EndpointInvites EndpointKind = "invites"
)
