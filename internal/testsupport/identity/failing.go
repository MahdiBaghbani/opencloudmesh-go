// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package tsidentity

import (
	"context"
	"errors"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

// ErrUnavailable simulates a backend store outage in tests.
var ErrUnavailable = errors.New("db unavailable")

// FailingSessionRepo implements identity.SessionRepo and fails every method.
type FailingSessionRepo struct{}

var _ identity.SessionRepo = (*FailingSessionRepo)(nil)

// Create always returns ErrUnavailable.
func (FailingSessionRepo) Create(_ context.Context, _ string, _ time.Duration) (*identity.Session, error) {
	return nil, ErrUnavailable
}

// Get always returns ErrUnavailable.
func (FailingSessionRepo) Get(_ context.Context, _ string) (*identity.Session, error) {
	return nil, ErrUnavailable
}

// Delete always returns ErrUnavailable.
func (FailingSessionRepo) Delete(_ context.Context, _ string) error {
	return ErrUnavailable
}

// DeleteByUser always returns ErrUnavailable.
func (FailingSessionRepo) DeleteByUser(_ context.Context, _ string) error {
	return ErrUnavailable
}

// DeleteExpired always returns ErrUnavailable.
func (FailingSessionRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, ErrUnavailable
}

// FailingPartyRepo implements identity.PartyRepo and fails every method.
type FailingPartyRepo struct{}

var _ identity.PartyRepo = (*FailingPartyRepo)(nil)

// Create always returns ErrUnavailable.
func (FailingPartyRepo) Create(_ context.Context, _ *identity.User) error {
	return ErrUnavailable
}

// Get always returns ErrUnavailable.
func (FailingPartyRepo) Get(_ context.Context, _ string) (*identity.User, error) {
	return nil, ErrUnavailable
}

// GetByUsername always returns ErrUnavailable.
func (FailingPartyRepo) GetByUsername(_ context.Context, _ string) (*identity.User, error) {
	return nil, ErrUnavailable
}

// GetByEmail always returns ErrUnavailable.
func (FailingPartyRepo) GetByEmail(_ context.Context, _ string) (*identity.User, error) {
	return nil, ErrUnavailable
}

// Update always returns ErrUnavailable.
func (FailingPartyRepo) Update(_ context.Context, _ *identity.User) error {
	return ErrUnavailable
}

// Delete always returns ErrUnavailable.
func (FailingPartyRepo) Delete(_ context.Context, _ string) error {
	return ErrUnavailable
}

// List always returns ErrUnavailable.
func (FailingPartyRepo) List(_ context.Context, _ string) ([]*identity.User, error) {
	return nil, ErrUnavailable
}

// DeleteExpired always returns ErrUnavailable.
func (FailingPartyRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, ErrUnavailable
}
