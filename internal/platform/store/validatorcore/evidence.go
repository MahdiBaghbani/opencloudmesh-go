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

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	evidenceAreaCapability      = "capability"
	evidenceStepFileOpened      = "file_opened"
	evidenceReasonTokenExchange = "token_exchange"
	evidenceReasonWebDAVGet     = "webdav_get"
	evidenceLegPassive          = "passive"
	evidenceLegForward          = "forward"
	evidenceLegReverse          = "reverse"

	// EvidenceLegPassive is the known passive evidence leg.
	EvidenceLegPassive = evidenceLegPassive
	// EvidenceLegForward is the known forward evidence leg.
	EvidenceLegForward = evidenceLegForward
	// EvidenceLegReverse is the known reverse evidence leg.
	EvidenceLegReverse = evidenceLegReverse
)

// ApplyEvidenceFactInput is one evidence observation for a validator session.
type ApplyEvidenceFactInput struct {
	TestRunID       string
	Area            string
	Step            string
	ReasonCode      string
	ExchangeID      *uint
	Severity        string
	AffectsGrade    bool
	PayloadRedacted string
	Leg             string
}

// ApplyEvidenceFact persists a first-wins evidence_row for the fact. A
// duplicate (test_run_id, leg, area, step, reason_code) is ignored. Empty or
// unknown legs and unknown areas are rejected so they cannot occupy the
// first-wins key and block a later valid fact. Only the winning insert of a
// forward capability file-open reason may attempt the non-terminal CAS from
// forward_share_sent to capability_exercise. A CAS miss is success.
// Reverse-leg capability file-open facts are ignored.
func (c *Core) ApplyEvidenceFact(ctx context.Context, in ApplyEvidenceFactInput) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateEvidenceFact(in); err != nil {
		return err
	}

	if isIgnoredReverseFileOpenedFact(in) {
		return nil
	}

	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return applyEvidenceFactTx(tx, in, now)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: apply evidence fact: %w", err)
	}

	return nil
}

// ReplaceEvidenceFact upserts last-wins for the same (test_run_id, leg, area,
// step) observation. A later severity, payload, or reason_code replaces the
// earlier row so a retry can supersede a transient grade. Capability CAS is
// not attempted.
func (c *Core) ReplaceEvidenceFact(ctx context.Context, in ApplyEvidenceFactInput) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateEvidenceFact(in); err != nil {
		return err
	}

	if isIgnoredReverseFileOpenedFact(in) {
		return nil
	}

	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return replaceEvidenceFactTx(tx, in, now)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: replace evidence fact: %w", err)
	}

	return nil
}

func validateEvidenceFact(in ApplyEvidenceFactInput) error {
	if in.TestRunID == "" {
		return errors.New("validatorcore: empty test_run_id")
	}

	if in.Area == "" {
		return errors.New("validatorcore: empty evidence area")
	}

	if !isKnownEvidenceArea(in.Area) {
		return errors.New("validatorcore: unknown evidence area")
	}

	if in.Step == "" {
		return errors.New("validatorcore: empty evidence step")
	}

	if in.ReasonCode == "" {
		return errors.New("validatorcore: empty evidence reason_code")
	}

	if in.Severity == "" {
		return errors.New("validatorcore: empty evidence severity")
	}

	if in.Leg == "" {
		return errors.New("validatorcore: empty evidence leg")
	}

	if !isKnownEvidenceLeg(in.Leg) {
		return errors.New("validatorcore: unknown evidence leg")
	}

	return nil
}

func isKnownEvidenceLeg(leg string) bool {
	switch leg {
	case evidenceLegPassive, evidenceLegForward, evidenceLegReverse:
		return true
	default:
		return false
	}
}

func isIgnoredReverseFileOpenedFact(in ApplyEvidenceFactInput) bool {
	capabilityFileOpened := in.Area == evidenceAreaCapability &&
		in.Step == evidenceStepFileOpened
	reverseLeg := in.Leg == evidenceLegReverse

	return capabilityFileOpened && reverseLeg
}

func isCapabilityAdvanceReason(reason string) bool {
	switch reason {
	case evidenceReasonTokenExchange, evidenceReasonWebDAVGet:
		return true
	default:
		return false
	}
}

func shouldAdvanceCapabilityExercise(in ApplyEvidenceFactInput) bool {
	canonicalAreaStep := in.Area == evidenceAreaCapability &&
		in.Step == evidenceStepFileOpened
	forwardLeg := in.Leg == evidenceLegForward

	return canonicalAreaStep && forwardLeg && isCapabilityAdvanceReason(in.ReasonCode)
}

func applyEvidenceFactTx(tx *gorm.DB, in ApplyEvidenceFactInput, now int64) error {
	inserted, err := insertEvidenceRowOrIgnore(tx, evidenceRowFromInput(in, now))
	if err != nil {
		return err
	}

	if !inserted || !shouldAdvanceCapabilityExercise(in) {
		return nil
	}

	return casCapabilityExerciseFromForwardShareSent(tx, in.TestRunID, now)
}

func replaceEvidenceFactTx(tx *gorm.DB, in ApplyEvidenceFactInput, now int64) error {
	err := tx.Where(
		"test_run_id = ? AND leg = ? AND area = ? AND step = ?",
		in.TestRunID,
		in.Leg,
		in.Area,
		in.Step,
	).Delete(&EvidenceRow{}).Error
	if err != nil {
		return err
	}

	return tx.Create(evidenceRowFromInput(in, now)).Error
}

func evidenceRowFromInput(in ApplyEvidenceFactInput, now int64) *EvidenceRow {
	var payload *string
	if in.PayloadRedacted != "" {
		payload = &in.PayloadRedacted
	}

	var leg *string

	if in.Leg != "" {
		copied := in.Leg
		leg = &copied
	}

	return &EvidenceRow{
		TestRunID:       in.TestRunID,
		Leg:             leg,
		Area:            in.Area,
		Step:            in.Step,
		ReasonCode:      in.ReasonCode,
		Severity:        in.Severity,
		AffectsGrade:    in.AffectsGrade,
		PayloadRedacted: payload,
		ExchangeID:      in.ExchangeID,
		CreatedAt:       now,
	}
}

func insertEvidenceRowOrIgnore(tx *gorm.DB, row *EvidenceRow) (bool, error) {
	if row == nil {
		return false, errors.New("validatorcore: nil evidence row")
	}

	res := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: colTestRunID},
			{Name: colLeg},
			{Name: colArea},
			{Name: colStep},
			{Name: colReasonCode},
		},
		DoNothing: true,
	}).Create(row)
	if res.Error != nil {
		return false, res.Error
	}

	return res.RowsAffected > 0, nil
}

func casCapabilityExerciseFromForwardShareSent(tx *gorm.DB, testRunID string, now int64) error {
	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateForwardShareSent).
		Updates(map[string]any{
			colState:     StateCapabilityExercise,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return res.Error
	}

	return nil
}
