// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package identitybind canonicalizes OCM invite identities for the
// federation-validator active path. Decoding happens before provider
// normalization; a base64-looking prefilter is never used.
package identitybind

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Identity is a decoded, provider-normalized OCM identity.
type Identity struct {
	LocalUser string
	Provider  string
	Opaque    bool
}

// Comparison reports host equality and whether the extracted local users
// can be enforced as plain identifiers.
type Comparison struct {
	HostsEqual      bool
	UsersEqual      bool
	UserEnforceable bool
}

// Canonicalize decodes a federated opaque ID when one is present, then
// normalizes the provider with hostport.Normalize. Ordinary localUser@provider
// addresses keep the parsed identifier.
func Canonicalize(raw, scheme string) (Identity, error) {
	if user, idp, ok := address.DecodeFederatedOpaqueID(raw); ok {
		return identityFromParts(user, idp, scheme, true)
	}

	identifier, provider, err := address.Parse(raw)
	if err != nil {
		return Identity{}, fmt.Errorf("identitybind: parse address: %w", err)
	}

	if user, idp, ok := address.DecodeFederatedOpaqueID(identifier); ok {
		return identityFromParts(user, idp, scheme, true)
	}

	return identityFromParts(identifier, provider, scheme, false)
}

func identityFromParts(user, idp, scheme string, opaque bool) (Identity, error) {
	provider, err := hostport.Normalize(idp, scheme)
	if err != nil {
		return Identity{}, fmt.Errorf("identitybind: normalize provider: %w", err)
	}

	return Identity{
		LocalUser: user,
		Provider:  provider,
		Opaque:    opaque,
	}, nil
}

// IsPlainLocalUser reports a non-empty local user that is not UUID-shaped.
func IsPlainLocalUser(localUser string) bool {
	if localUser == "" {
		return false
	}

	if _, err := uuid.Parse(localUser); err == nil {
		return false
	}

	return true
}

// Compare reports host and user equality after Canonicalize. User comparison
// is enforceable only when both sides are non-opaque plain local users.
func Compare(left, right Identity) Comparison {
	return Comparison{
		HostsEqual:      left.Provider == right.Provider,
		UsersEqual:      left.LocalUser == right.LocalUser,
		UserEnforceable: userEnforceable(left) && userEnforceable(right),
	}
}

func userEnforceable(id Identity) bool {
	return !id.Opaque && IsPlainLocalUser(id.LocalUser)
}
