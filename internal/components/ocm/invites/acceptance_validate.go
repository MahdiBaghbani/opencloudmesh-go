// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites

import (
	"errors"
	"strings"
)

var (
	// ErrInvalidAcceptedIdentity reports an accepted-status write whose remote
	// identity (user id plus normalized provider host) is incomplete after
	// coalescing with the stored record.
	ErrInvalidAcceptedIdentity = errors.New("invalid accepted identity")
	// ErrInvalidCreateStatus reports a create whose initial status is accepted
	// without the full remote identity.
	ErrInvalidCreateStatus = errors.New("invalid create status")
)

// ValidateAcceptedIdentity enforces the acceptance identity invariant: an
// accepted status must carry both the remote user id and the normalized
// provider host. Other statuses carry no identity requirement.
func ValidateAcceptedIdentity(status, userID, normalizedHost string) error {
	if acceptedIdentityMissing(status, userID, normalizedHost) {
		return ErrInvalidAcceptedIdentity
	}

	return nil
}

// ValidateCreateInviteStatus enforces the same invariant at create time: a
// record created directly in accepted status must carry the full identity.
func ValidateCreateInviteStatus(status, userID, normalizedHost string) error {
	if acceptedIdentityMissing(status, userID, normalizedHost) {
		return ErrInvalidCreateStatus
	}

	return nil
}

// CoalesceAcceptedIdentity resolves the effective accepted identity for an
// update: argument values win when non-empty, otherwise the stored values
// carry over so a partial write cannot erase a persisted identity. Only the
// user id and the normalized host coalesce; the raw provider host follows
// replace semantics and is not handled here.
func CoalesceAcceptedIdentity(argUserID, argHost, existingUserID, existingHost string) (userID, host string) {
	userID = argUserID
	if strings.TrimSpace(userID) == "" {
		userID = existingUserID
	}

	host = argHost
	if strings.TrimSpace(host) == "" {
		host = existingHost
	}

	return userID, host
}

// ValidateUpdateAcceptedIdentity validates an accepted-status update against
// the coalesced identity: arguments win when present, stored values fill the
// gaps, and the result must still be complete.
func ValidateUpdateAcceptedIdentity(status, argUserID, argHost, existingUserID, existingHost string) error {
	userID, host := CoalesceAcceptedIdentity(argUserID, argHost, existingUserID, existingHost)

	return ValidateAcceptedIdentity(status, userID, host)
}

// acceptedIdentityMissing reports whether an accepted status lacks the full
// remote identity. Whitespace-only values count as empty.
func acceptedIdentityMissing(status, userID, normalizedHost string) bool {
	return status == string(InviteStatusAccepted) &&
		(strings.TrimSpace(userID) == "" || strings.TrimSpace(normalizedHost) == "")
}
