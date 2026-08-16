// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// StatsHostHasher hashes a normalized host authority for statistics export.
type StatsHostHasher interface {
	HashHost(host string) (string, error)
}

// SetStatsHostHasher wires keyed host hashing for terminal statistics persistence.
func (c *Core) SetStatsHostHasher(hasher StatsHostHasher) {
	if c == nil {
		return
	}

	c.statsHasher = hasher
}

// SetSessionContribute records per-session statistics opt-in for testRunID.
// contribute is not persisted as a database column; it lives in memory until
// terminalization clears it.
func (c *Core) SetSessionContribute(testRunID string, contribute bool) {
	if c == nil || testRunID == "" || !contribute {
		return
	}

	c.sessionContrib.Store(testRunID, true)
}

func (c *Core) sessionContributes(testRunID string) bool {
	if c == nil || testRunID == "" {
		return false
	}

	value, ok := c.sessionContrib.Load(testRunID)
	if !ok {
		return false
	}

	contribute, ok := value.(bool)

	return ok && contribute
}

func (c *Core) clearSessionContribute(testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.sessionContrib.Delete(testRunID)
}

// SetTerminalStatsSnapshot stores the in-memory terminal grade snapshot for
// testRunID until terminal stats persistence completes. Conformance wiring will
// populate area grades here; TestRun.overall_grade is not mapped into stats_raw
// because DeriveHealthy reads area grade columns only.
func (c *Core) SetTerminalStatsSnapshot(testRunID string, snap StatsSnapshot) {
	if c == nil || testRunID == "" {
		return
	}

	c.terminalStatsSnapshots.Store(testRunID, snap)
}

func (c *Core) terminalStatsOverlay(testRunID string) (*StatsSnapshot, bool) {
	if c == nil || testRunID == "" {
		return nil, false
	}

	value, ok := c.terminalStatsSnapshots.Load(testRunID)
	if !ok {
		return nil, false
	}

	snap, ok := value.(StatsSnapshot)
	if !ok {
		return nil, false
	}

	return &snap, true
}

func (c *Core) clearTerminalStatsOverlay(testRunID string) {
	if c == nil || testRunID == "" {
		return
	}

	c.terminalStatsSnapshots.Delete(testRunID)
}

func (c *Core) clearTerminalStatsState(testRunID string) {
	c.clearSessionContribute(testRunID)
	c.clearTerminalStatsOverlay(testRunID)
}

// persistTerminalStats writes one stats_raw row and increments stats_aggregate
// when the session opted in at request time. Incognito sessions write nothing.
// Errors are returned for observability; callers treat persistence as best-effort
// after the session is already terminal.
func (c *Core) persistTerminalStats(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if !c.sessionContributes(testRunID) {
		c.clearTerminalStatsState(testRunID)

		return nil
	}

	defer c.clearTerminalStatsState(testRunID)

	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: load test run for stats: %w", err)
	}

	if row.FinishedAt == nil {
		return errors.New("validatorcore: terminal stats require finished_at")
	}

	hostHash, err := c.hashHostForTestRun(row)
	if err != nil {
		return fmt.Errorf("validatorcore: hash target host: %w", err)
	}

	overlay, _ := c.terminalStatsOverlay(testRunID)
	snap := statsSnapshotFromTestRun(row, hostHash, *row.FinishedAt, overlay)
	raw := snap.ToStatsRaw()

	if err := c.insertStatsRawAndAggregate(ctx, &raw); err != nil {
		return err
	}

	return nil
}

func statsSnapshotFromTestRun(row *TestRun, hostHash string, finishedAt int64, overlay *StatsSnapshot) StatsSnapshot {
	kind := row.SessionKind
	if kind == "" {
		kind = SessionKindPassiveOnly
	}

	snap := StatsSnapshot{
		HostHash:    hostHash,
		SessionKind: kind,
		CreatedAt:   finishedAt,
	}

	if overlay != nil {
		mergeTerminalStatsOverlay(&snap, overlay)
	}

	return snap
}

func mergeTerminalStatsOverlay(dst *StatsSnapshot, overlay *StatsSnapshot) {
	if dst == nil || overlay == nil {
		return
	}

	dst.ReverseInviteExercised = overlay.ReverseInviteExercised
	dst.Platform = overlay.Platform
	dst.APIVersion = overlay.APIVersion
	dst.GradeDiscovery = overlay.GradeDiscovery
	dst.GradeTLS = overlay.GradeTLS
	dst.GradeJWKS = overlay.GradeJWKS
	dst.GradeHTTPSig = overlay.GradeHTTPSig
	dst.GradeSharing = overlay.GradeSharing
	dst.GradeNotification = overlay.GradeNotification
	dst.GradeToken = overlay.GradeToken
	dst.GradeCapability = overlay.GradeCapability
	dst.WindowBucket = overlay.WindowBucket
}

func (c *Core) hashHostForTestRun(row *TestRun) (string, error) {
	if c.statsHasher == nil {
		return "", errors.New("validatorcore: stats host hasher is not configured")
	}

	if row == nil {
		return "", errors.New("validatorcore: nil test run")
	}

	authority, scheme, err := targetOriginAuthority(row.TargetOrigin)
	if err != nil {
		return "", err
	}

	normalized, err := normalizeStatsHost(authority, scheme)
	if err != nil {
		return "", err
	}

	hashed, hashErr := c.statsHasher.HashHost(normalized)
	if hashErr != nil {
		return "", fmt.Errorf("validatorcore: stats host hash: %w", hashErr)
	}

	return hashed, nil
}

func targetOriginAuthority(targetOrigin string) (authority, scheme string, err error) {
	parsed, parseErr := url.Parse(targetOrigin)
	if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", errors.New("validatorcore: invalid target origin")
	}

	return parsed.Host, parsed.Scheme, nil
}

func isTerminalState(state string) bool {
	return state == StateTerminalPass || state == StateTerminalFail
}

func normalizeStatsHost(authority, scheme string) (string, error) {
	normalized, err := hostport.Normalize(authority, scheme)
	if err != nil {
		return "", fmt.Errorf("validatorcore: normalize stats host: %w", err)
	}

	return normalized, nil
}

func bestEffortPersistTerminalStats(c *Core, ctx context.Context, testRunID string) {
	statsCtx := context.WithoutCancel(ctx)

	if err := c.persistTerminalStats(statsCtx, testRunID); err != nil {
		appctx.GetLogger(ctx).Error(
			"validator terminal stats persistence failed",
			slog.String("test_run_id", testRunID),
			slog.Any("error", err),
		)
	}
}
