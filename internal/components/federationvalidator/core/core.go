// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package core holds federation validator shared state wired at startup.
package core

import (
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

// Core holds federation validator infrastructure shared across passive and active
// scan surfaces. Statistics salt plumbing is wired at startup.
//
// Shared-core integration hooks remain intentionally unwired on Core; session and
// correlation persistence is provided by the validatorcore package instead:
//   - FindOneActive
//   - FindActiveCorrelation (confirmed-only)
//   - FindCorrelationAnyStatus (pending-inclusive)
//   - reverse-plane open window
//
// Do not add members, interfaces, SQL, or logic for these hooks on Core until
// their wiring is implemented.
type Core struct {
	// statsSalt is the shared 32-byte redaction salt (additive).
	statsSalt []byte

	// hashHost returns a keyed BLAKE3 hex digest for a lowercase host label
	// (additive).
	hashHost func(host string) (string, error)
}

// New builds a Core from the startup-loaded redaction salt.
func New(salt []byte) (*Core, error) {
	if len(salt) != statistics.RedactionSaltSize {
		return nil, fmt.Errorf("federationvalidator core: salt must be %d bytes", statistics.RedactionSaltSize)
	}

	key := make([]byte, statistics.RedactionSaltSize)
	copy(key, salt)

	return &Core{
		statsSalt: key,
		hashHost: func(host string) (string, error) {
			return statistics.HashStatsHost(key, host)
		},
	}, nil
}

// StatsSalt returns a copy of the shared redaction/statistics salt.
func (c *Core) StatsSalt() []byte {
	if c == nil || len(c.statsSalt) == 0 {
		return nil
	}

	out := make([]byte, len(c.statsSalt))
	copy(out, c.statsSalt)

	return out
}

// HashHost hashes a host for statistics export using stats-host|<lowercase_host>.
func (c *Core) HashHost(host string) (string, error) {
	if c == nil || c.hashHost == nil {
		return "", errors.New("federationvalidator core: hashHost is not configured")
	}

	return c.hashHost(host)
}
