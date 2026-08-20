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
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// StatsHostHasher provides keyed hashing for statistics export: host hashing
// and stats_raw row dedup keys.
type StatsHostHasher interface {
	HashHost(host string) (string, error)
	HashStatsK(value string) (string, error)
}

// SetStatsHostHasher wires keyed host hashing for terminal statistics persistence.
func (c *Core) SetStatsHostHasher(hasher StatsHostHasher) {
	if c == nil {
		return
	}

	c.statsHasher = hasher
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
	c.clearTerminalStatsOverlay(testRunID)
}

// persistTerminalStats writes one stats_raw row and rebuilds the per-host
// stats_aggregate atomically when the persisted test_run opted into
// statistics. Incognito and permanent-only sessions write nothing. Consent is
// read from the persisted row so it survives process restart, and
// stats_written_at is the write-once marker that makes retries no-ops.
// Errors are returned for observability; callers treat persistence as
// best-effort after the session is already terminal.
func (c *Core) persistTerminalStats(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: load test run for stats: %w", err)
	}

	if !row.OptInStats {
		c.clearTerminalStatsState(testRunID)

		return nil
	}

	defer c.clearTerminalStatsState(testRunID)

	if row.FinishedAt == nil {
		return errors.New("validatorcore: terminal stats require finished_at")
	}

	hostHash, err := c.hashHostForTestRun(row)
	if err != nil {
		return fmt.Errorf("validatorcore: hash target host: %w", err)
	}

	k, err := c.statsHasher.HashStatsK(testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: stats row key: %w", err)
	}

	overlay, _ := c.terminalStatsOverlay(testRunID)
	snap := statsSnapshotFromTestRun(row, hostHash, *row.FinishedAt, overlay)

	if err := c.writeTerminalStats(ctx, testRunID, hostHash, k, &snap); err != nil {
		return err
	}

	return nil
}

// writeTerminalStats runs the atomic stats write in one transaction: the
// write-once stats_written_at guard, one stats_raw insert keyed by the run's
// dedup key, and a per-host aggregate rebuild. A zero-row guard result means
// stats were already written (or consent was revoked after the reload), so
// the call is a no-op. A dedup-key conflict on stats_raw means the row is
// already counted, so the aggregate is left untouched.
func (c *Core) writeTerminalStats(
	ctx context.Context,
	testRunID, hostHash, k string,
	snap *StatsSnapshot,
) error {
	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(
			"UPDATE test_run SET stats_written_at = ? "+
				"WHERE test_run_id = ? AND opt_in_stats = 1 AND stats_written_at IS NULL",
			now, testRunID,
		)
		if res.Error != nil {
			return fmt.Errorf("validatorcore: stamp stats_written_at: %w", res.Error)
		}

		if res.RowsAffected == 0 {
			return nil
		}

		if err := fillSnapshotGradesFromEvidence(tx, testRunID, snap); err != nil {
			return fmt.Errorf("validatorcore: load evidence grades: %w", err)
		}

		raw := snap.ToStatsRaw()
		raw.K = k

		inserted, err := insertStatsRawOrIgnore(tx, &raw)
		if err != nil {
			return fmt.Errorf("validatorcore: insert stats_raw: %w", err)
		}

		if !inserted {
			return nil
		}

		if err := rebuildStatsAggregateForHost(tx, hostHash); err != nil {
			return fmt.Errorf("validatorcore: rebuild stats aggregate: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: persist terminal stats writes: %w", err)
	}

	return nil
}

// fillSnapshotGradesFromEvidence derives area grades from grade-affecting
// evidence_row entries and fills only the snapshot's missing grade slots;
// overlay grades always win. It is a read folded into the persist
// transaction, not a second write path.
func fillSnapshotGradesFromEvidence(tx *gorm.DB, testRunID string, snap *StatsSnapshot) error {
	var rows []EvidenceRow
	if err := tx.
		Select("area", "severity").
		Where("test_run_id = ? AND affects_grade = ?", testRunID, true).
		Find(&rows).Error; err != nil {
		return err
	}

	if len(rows) == 0 {
		return nil
	}

	worst := make(map[string]string, len(rows))

	for _, row := range rows {
		grade := evidenceSeverityGrade(row.Severity)

		if existing, ok := worst[row.Area]; ok {
			worst[row.Area] = worseGrade(existing, grade)

			continue
		}

		worst[row.Area] = grade
	}

	for area, grade := range worst {
		slot := statsSnapshotGradeSlot(snap, area)
		if slot == nil || *slot != nil {
			continue
		}

		derived := grade
		*slot = &derived
	}

	return nil
}

// evidenceSeverityGrade maps an evidence_row severity label to a stats grade.
// Fail-like severities dominate, then warn-like; any other grade-affecting
// row means the area was exercised without a finding, which reads as pass.
func evidenceSeverityGrade(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "fail", "failure", "critical", "error", "fatal":
		return GradeFail
	case "warn", "warning", "important":
		return GradeWarn
	default:
		return GradePass
	}
}

func worseGrade(a, b string) string {
	if a == GradeFail || b == GradeFail {
		return GradeFail
	}

	if a == GradeWarn || b == GradeWarn {
		return GradeWarn
	}

	return GradePass
}

// statsSnapshotGradeSlot returns the snapshot's grade slot for an evidence
// area, or nil for areas outside the statistics grade set. Area names mirror
// the public statistics area ordering in stats_areas.go.
func statsSnapshotGradeSlot(snap *StatsSnapshot, area string) **string {
	switch area {
	case "discovery":
		return &snap.GradeDiscovery
	case "tls":
		return &snap.GradeTLS
	case "jwks":
		return &snap.GradeJWKS
	case "httpsig":
		return &snap.GradeHTTPSig
	case "sharing":
		return &snap.GradeSharing
	case "notification":
		return &snap.GradeNotification
	case "token":
		return &snap.GradeToken
	case "capability":
		return &snap.GradeCapability
	default:
		return nil
	}
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
	dst.ConnectionReport = cloneConnectionReport(overlay.ConnectionReport)
}

func cloneConnectionReport(src *StatsConnectionReport) *StatsConnectionReport {
	if src == nil {
		return nil
	}

	dst := *src
	dst.LeafSANs = append([]string(nil), src.LeafSANs...)
	dst.ReasonCodes = append([]string(nil), src.ReasonCodes...)

	return &dst
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
	return state == StateTerminalPass || state == StateTerminalFail || state == StateInterrupted
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
