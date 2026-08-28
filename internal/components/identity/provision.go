// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	sessionInviterUsernamePrefix  = "session-inviter-"
	sessionInviterDisplayName     = "Session Inviter"
	sessionReceiverUsernamePrefix = "session-receiver-"
	defaultReceiverDisplayName    = "Probe User"
)

// ErrPartyIdentityMismatch is returned when a prescribed party ID already
// exists but username, email, role, or realm do not match the request.
var ErrPartyIdentityMismatch = errors.New("party identity does not match prescribed id")

// PartySpec is a prescribed-identity party to create or return.
type PartySpec struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	Role        string
	Realm       string
	StorageRoot string
}

// ReverseReceiverSpec is the probe identity for the reverse-invite recipient.
type ReverseReceiverSpec struct {
	ID          string
	Email       string
	DisplayName string
	Realm       string
}

// EnsureParty creates the prescribed party or returns the existing one when
// the stored identity is compatible. A username or email owned by a different
// ID is a hard error; that occupant is never reused for the prescribed ID.
func EnsureParty(ctx context.Context, repo PartyRepo, spec PartySpec) (*User, error) {
	if err := validatePartySpec(repo, spec); err != nil {
		return nil, err
	}

	existing, err := repo.Get(ctx, spec.ID)
	if err == nil {
		return acceptExistingParty(existing, spec)
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("identity: get party: %w", err)
	}

	indexed, lookupErr := lookupIndexedParty(ctx, repo, spec)
	if lookupErr == nil {
		return acceptExistingParty(indexed, spec)
	}

	if !errors.Is(lookupErr, ErrUserNotFound) {
		return nil, lookupErr
	}

	user := newPrescribedParty(spec)
	if err := repo.Create(ctx, user); err != nil {
		return resolvePartyCreateConflict(ctx, repo, spec, err)
	}

	return user, nil
}

// EnsureSessionInviter materializes Alice: party ID is the session test-run
// ID, username is session-inviter-<id>, and expiry stays unset.
func EnsureSessionInviter(ctx context.Context, repo PartyRepo, testRunID, realm string) (*User, error) {
	if testRunID == "" {
		return nil, errors.New("identity: session inviter id is required")
	}

	return EnsureParty(ctx, repo, PartySpec{
		ID:          testRunID,
		Username:    sessionInviterUsernamePrefix + testRunID,
		DisplayName: sessionInviterDisplayName,
		Role:        RoleProbe,
		Realm:       realm,
	})
}

// EnsureReverseReceiver materializes Bob with the prescribed bob user ID
// and the configured probe email and display name. Username is scoped to
// the prescribed ID so a later session never reuses another party's login.
func EnsureReverseReceiver(ctx context.Context, repo PartyRepo, spec ReverseReceiverSpec) (*User, error) {
	if spec.ID == "" {
		return nil, errors.New("identity: reverse receiver id is required")
	}

	displayName := spec.DisplayName
	if displayName == "" {
		displayName = defaultReceiverDisplayName
	}

	return EnsureParty(ctx, repo, PartySpec{
		ID:          spec.ID,
		Username:    sessionReceiverUsernamePrefix + spec.ID,
		Email:       scopedProbeEmail(spec.Email, spec.ID),
		DisplayName: displayName,
		Role:        RoleProbe,
		Realm:       spec.Realm,
	})
}

func validatePartySpec(repo PartyRepo, spec PartySpec) error {
	if repo == nil {
		return errors.New("identity: party repo is not configured")
	}

	if spec.ID == "" {
		return errors.New("identity: prescribed party id is required")
	}

	if spec.Username == "" {
		return errors.New("identity: prescribed username is required")
	}

	return nil
}

func newPrescribedParty(spec PartySpec) *User {
	return &User{
		ID:          spec.ID,
		Username:    spec.Username,
		Email:       spec.Email,
		DisplayName: spec.DisplayName,
		Role:        spec.Role,
		Realm:       spec.Realm,
		StorageRoot: spec.StorageRoot,
		CreatedAt:   time.Now(),
		ExpiresAt:   nil,
	}
}

func acceptExistingParty(existing *User, spec PartySpec) (*User, error) {
	if !partyCompatible(existing, spec) {
		return nil, fmt.Errorf("identity: %w", ErrPartyIdentityMismatch)
	}

	return existing, nil
}

func partyCompatible(existing *User, spec PartySpec) bool {
	if existing == nil {
		return false
	}

	usernameMatch := existing.Username == spec.Username
	emailMatch := spec.Email == "" || existing.Email == spec.Email
	roleMatch := spec.Role == "" || existing.Role == spec.Role
	realmMatch := spec.Realm == "" || existing.Realm == spec.Realm

	return usernameMatch && emailMatch && roleMatch && realmMatch
}

func lookupIndexedParty(ctx context.Context, repo PartyRepo, spec PartySpec) (*User, error) {
	occupant, err := repo.GetByUsername(ctx, spec.Username)
	if err == nil {
		if occupant.ID != spec.ID {
			return nil, fmt.Errorf("identity: %w", ErrUserExists)
		}

		return occupant, nil
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("identity: get party by username: %w", err)
	}

	if spec.Email == "" {
		return nil, ErrUserNotFound
	}

	byEmail, err := repo.GetByEmail(ctx, spec.Email)
	if err == nil {
		if byEmail.ID != spec.ID {
			return nil, fmt.Errorf("identity: %w", ErrEmailExists)
		}

		return byEmail, nil
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("identity: get party by email: %w", err)
	}

	return nil, ErrUserNotFound
}

func resolvePartyCreateConflict(
	ctx context.Context,
	repo PartyRepo,
	spec PartySpec,
	createErr error,
) (*User, error) {
	switch {
	case errors.Is(createErr, ErrUserIDExists):
		existing, err := repo.Get(ctx, spec.ID)
		if err != nil {
			return nil, fmt.Errorf("identity: get party after id conflict: %w", err)
		}

		return acceptExistingParty(existing, spec)
	case errors.Is(createErr, ErrUserExists):
		occupant, err := repo.GetByUsername(ctx, spec.Username)
		if err != nil {
			return nil, fmt.Errorf("identity: get party after username conflict: %w", err)
		}

		if occupant.ID != spec.ID {
			return nil, fmt.Errorf("identity: %w", ErrUserExists)
		}

		return acceptExistingParty(occupant, spec)
	case errors.Is(createErr, ErrEmailExists):
		return nil, fmt.Errorf("identity: %w", ErrEmailExists)
	default:
		return nil, fmt.Errorf("identity: create party: %w", createErr)
	}
}

func scopedProbeEmail(email, id string) string {
	if email == "" || id == "" {
		return email
	}

	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return email
	}

	return local + "+" + id + "@" + domain
}
