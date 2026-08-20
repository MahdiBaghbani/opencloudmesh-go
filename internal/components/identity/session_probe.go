// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SessionProbeUsername is the stable login name for the session probe party.
const SessionProbeUsername = "probe"

const defaultSessionProbeDisplayName = "Probe User"

// ErrSessionProbeRealmMismatch is returned when a reusable probe belongs to a
// different realm than the requested session probe.
var ErrSessionProbeRealmMismatch = errors.New("session probe realm mismatch")

// SessionProbeUserSpec describes the local session probe party to create or reuse.
// Email and display name typically come from [validator.probe]; realm is the
// derived local provider domain. The party ID is always a minted or reused
// UUIDv7 and is never a session test-run identifier.
type SessionProbeUserSpec struct {
	Email       string
	DisplayName string
	Username    string
	Password    string
	Realm       string
	StorageRoot string
	// TestRunID is the session test-run identifier when the caller has one.
	// CreateSessionProbeUser never uses it as the probe party ID.
	TestRunID string
}

// CreateSessionProbeUser creates the session-scoped probe party, or returns the
// existing probe party when one is already present. ExpiresAt stays nil so
// DeleteExpired does not remove it; later prune keep-rules decide lifetime.
func CreateSessionProbeUser(
	ctx context.Context,
	repo PartyRepo,
	auth *UserAuth,
	spec SessionProbeUserSpec,
) (*User, error) {
	if repo == nil {
		return nil, errors.New("identity: party repo is not configured")
	}

	if auth == nil {
		return nil, errors.New("identity: user auth is not configured")
	}

	username := spec.Username
	if username == "" {
		username = SessionProbeUsername
	}

	existing, err := repo.GetByUsername(ctx, username)
	if err == nil {
		return reuseExistingSessionProbe(
			ctx,
			repo,
			existing,
			ErrUserExists,
			spec.Realm,
		)
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("identity: get session probe user: %w", err)
	}

	if spec.Email != "" {
		byEmail, emailErr := repo.GetByEmail(ctx, spec.Email)
		if emailErr == nil {
			return reuseExistingSessionProbe(
				ctx,
				repo,
				byEmail,
				ErrEmailExists,
				spec.Realm,
			)
		}

		if !errors.Is(emailErr, ErrUserNotFound) {
			return nil, fmt.Errorf("identity: get session probe user by email: %w", emailErr)
		}
	}

	user, err := newSessionProbeUser(auth, spec, username)
	if err != nil {
		return nil, err
	}

	if err := repo.Create(ctx, user); err != nil {
		reused, reuseErr := reuseSessionProbeAfterCreateConflict(
			ctx,
			repo,
			spec,
			username,
			err,
		)
		if reuseErr == nil {
			return reused, nil
		}

		if !errors.Is(reuseErr, err) {
			return nil, reuseErr
		}

		return nil, fmt.Errorf("identity: create session probe user: %w", err)
	}

	return user, nil
}

func newSessionProbeUser(auth *UserAuth, spec SessionProbeUserSpec, username string) (*User, error) {
	password := spec.Password
	if password == "" {
		generated, err := GenerateRandomPassword()
		if err != nil {
			return nil, err
		}

		password = generated
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	id, err := mintSessionProbeID(spec.TestRunID)
	if err != nil {
		return nil, err
	}

	displayName := spec.DisplayName
	if displayName == "" {
		displayName = defaultSessionProbeDisplayName
	}

	return &User{
		ID:           id,
		Username:     username,
		Email:        spec.Email,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         RoleProbe,
		Realm:        spec.Realm,
		StorageRoot:  spec.StorageRoot,
		CreatedAt:    time.Now(),
		ExpiresAt:    nil,
	}, nil
}

func mintSessionProbeID(testRunID string) (string, error) {
	id, err := UUIDv7()
	if err != nil {
		return "", err
	}

	if testRunID != "" && id == testRunID {
		id, err = UUIDv7()
		if err != nil {
			return "", err
		}
	}

	return id, nil
}

func reuseSessionProbeAfterCreateConflict(
	ctx context.Context,
	repo PartyRepo,
	spec SessionProbeUserSpec,
	username string,
	createErr error,
) (*User, error) {
	var (
		existing *User
		err      error
	)

	switch {
	case errors.Is(createErr, ErrUserExists):
		existing, err = repo.GetByUsername(ctx, username)
	case errors.Is(createErr, ErrEmailExists):
		if spec.Email == "" {
			return nil, createErr
		}

		existing, err = repo.GetByEmail(ctx, spec.Email)
	default:
		return nil, createErr
	}

	if err != nil {
		return nil, fmt.Errorf("identity: get session probe user after create: %w", err)
	}

	return reuseExistingSessionProbe(ctx, repo, existing, createErr, spec.Realm)
}

// reuseExistingSessionProbe returns an existing probe only when it is a
// session probe whose realm matches. A TTL-bearing probe is not reusable as-is:
// ExpiresAt is cleared so DeleteExpired cannot remove the session probe.
func reuseExistingSessionProbe(
	ctx context.Context,
	repo PartyRepo,
	existing *User,
	conflict error,
	realm string,
) (*User, error) {
	if existing == nil || !existing.IsProbe() {
		return nil, conflict
	}

	if existing.Realm != realm {
		return nil, ErrSessionProbeRealmMismatch
	}

	if existing.ExpiresAt == nil {
		return existing, nil
	}

	existing.ExpiresAt = nil
	if err := repo.Update(ctx, existing); err != nil {
		return nil, fmt.Errorf("identity: clear session probe expiry: %w", err)
	}

	return existing, nil
}
