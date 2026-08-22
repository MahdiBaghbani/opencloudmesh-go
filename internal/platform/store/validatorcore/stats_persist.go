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

// persistTerminalStats writes one stats_raw row when the persisted test_run
// opted into statistics. Incognito and permanent-only sessions write
// nothing. Consent is read from the persisted row so it survives process
// restart, and stats_written_at is the write-once marker that makes retries
// no-ops. Errors are returned for observability; callers treat persistence
// as best-effort after the session is already terminal.
func (c *Core) persistTerminalStats(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("validatorcore: load test run for stats: %w", err)
	}

	if !row.OptInStats {
		return nil
	}

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

	snap := statsSnapshotFromTestRun(row, hostHash, *row.FinishedAt)

	if err := c.writeTerminalStats(ctx, testRunID, k, &snap); err != nil {
		return err
	}

	return nil
}

// writeTerminalStats runs the atomic stats write in one transaction: the
// write-once stats_written_at guard and one stats_raw insert keyed by the
// run's dedup key. A zero-row guard result means stats were already written
// (or consent was revoked after the reload), so the call is a no-op. A
// dedup-key conflict on stats_raw means the row is already counted.
func (c *Core) writeTerminalStats(
	ctx context.Context,
	testRunID, k string,
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

		if err := fillSnapshotGradesFromRating(tx, testRunID, snap); err != nil {
			return fmt.Errorf("validatorcore: fill snapshot grades from rating: %w", err)
		}

		raw := snap.ToStatsRaw()
		raw.K = k

		if _, err := insertStatsRawOrIgnore(tx, &raw); err != nil {
			return fmt.Errorf("validatorcore: insert stats_raw: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("validatorcore: persist terminal stats writes: %w", err)
	}

	return nil
}

// fillSnapshotGradesFromRating derives area grades from grade-affecting
// evidence rows using the same fold as RateSpecification. It fills only
// the snapshot's missing grade slots. Reverse-invite acceptance marks
// sharing as exercised. It is a read folded into the persist transaction,
// not a second write path.
func fillSnapshotGradesFromRating(tx *gorm.DB, testRunID string, snap *StatsSnapshot) error {
	if snap == nil {
		return errors.New("validatorcore: nil stats snapshot")
	}

	var rows []EvidenceRow
	if err := tx.
		Where("test_run_id = ? AND affects_grade = ?", testRunID, true).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return err
	}

	areas := foldSpecificationAreas(rows)

	for _, area := range areas {
		if area.Grade == nil {
			continue
		}

		slot := statsSnapshotGradeSlot(snap, area.Area)
		if slot == nil || *slot != nil {
			continue
		}

		derived := *area.Grade
		*slot = &derived
	}

	if hasReverseInviteAcceptance(rows) {
		snap.ReverseInviteExercised = true
	}

	return nil
}

// statsSnapshotGradeSlot returns the snapshot's grade slot for a scored
// area, or nil for areas outside the statistics grade set.
func statsSnapshotGradeSlot(snap *StatsSnapshot, area string) **string {
	switch area {
	case SpecificationAreaDiscovery:
		return &snap.GradeDiscovery
	case SpecificationAreaTLS:
		return &snap.GradeTLS
	case SpecificationAreaJWKS:
		return &snap.GradeJWKS
	case SpecificationAreaHTTPSig:
		return &snap.GradeHTTPSig
	case SpecificationAreaSharing:
		return &snap.GradeSharing
	case SpecificationAreaNotification:
		return &snap.GradeNotification
	case SpecificationAreaToken:
		return &snap.GradeToken
	case SpecificationAreaCapability:
		return &snap.GradeCapability
	default:
		return nil
	}
}

func statsSnapshotFromTestRun(row *TestRun, hostHash string, finishedAt int64) StatsSnapshot {
	snap := StatsSnapshot{
		HostHash:    hostHash,
		SessionKind: SessionKindOf(row),
		CreatedAt:   finishedAt,
	}

	if row == nil {
		return snap
	}

	if row.Platform != nil {
		snap.Platform = *row.Platform
	}

	if row.APIVersion != nil {
		snap.APIVersion = *row.APIVersion
	}

	return snap
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

// isPrunableTerminalState reports whether retention may delete or tombstone
// the row. Interrupted stays writer-terminal so a later resume or flip can
// still find it.
func isPrunableTerminalState(state string) bool {
	return state == StateTerminalPass || state == StateTerminalFail
}

func prunableTerminalStateSet() []string {
	states := make([]string, 0, len(testRunStates))

	for _, state := range testRunStates {
		if isPrunableTerminalState(state) {
			states = append(states, state)
		}
	}

	return states
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
