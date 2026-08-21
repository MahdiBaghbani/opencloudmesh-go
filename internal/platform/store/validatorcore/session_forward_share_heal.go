// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// HealForwardSharePresence re-applies each forward capability file-opened
// fact whose evidence row is already present through the shared evidence
// seam, then runs the same allowed forward_share_sent -> capability_exercise
// advance directly. The seam's advance is insert-gated, so a pre-existing
// evidence row can never fire it; the presence-gated direct advance closes
// that gap with the identical from-set and leaves a run that already moved
// on untouched.
func (c *Core) HealForwardSharePresence(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	for _, reason := range []string{evidenceReasonTokenExchange, evidenceReasonWebDAVGet} {
		present, err := c.hasEvidenceFact(ctx, testRunID, evidenceAreaCapability, evidenceStepFileOpened, reason)
		if err != nil {
			return err
		}

		if !present {
			continue
		}

		if err := c.ApplyEvidenceFact(ctx, ApplyEvidenceFactInput{
			TestRunID:    testRunID,
			Area:         evidenceAreaCapability,
			Step:         evidenceStepFileOpened,
			ReasonCode:   reason,
			Severity:     GradePass,
			AffectsGrade: true,
			Leg:          evidenceLegForward,
		}); err != nil {
			return err
		}

		if err := c.advanceCapabilityExerciseFromForwardShareSent(ctx, testRunID); err != nil {
			return err
		}
	}

	return nil
}

func (c *Core) hasEvidenceFact(ctx context.Context, testRunID, area, step, reason string) (bool, error) {
	var count int64

	if err := c.db.WithContext(ctx).Model(&EvidenceRow{}).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?", testRunID, area, step, reason).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf("validatorcore: count evidence fact: %w", err)
	}

	return count > 0, nil
}

func (c *Core) advanceCapabilityExerciseFromForwardShareSent(ctx context.Context, testRunID string) error {
	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateForwardShareSent).
		Updates(map[string]any{
			colState:     StateCapabilityExercise,
			colUpdatedAt: time.Now().Unix(),
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: heal capability exercise advance: %w", res.Error)
	}

	return nil
}
