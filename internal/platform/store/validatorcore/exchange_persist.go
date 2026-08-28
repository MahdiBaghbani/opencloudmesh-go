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

// ActiveExchangeDraft is one path-only HTTP transcript for an active leg.
// Callers must not put hosts, query strings, tokens, invite strings, headers,
// or bodies on the draft; those stay off the persisted row.
type ActiveExchangeDraft struct {
	TestRunID  string
	EndpointID string
	Method     string
	URL        string
	Direction  string
	RequestID  string
	StatusCode int
	Leg        string
	Actor      string
}

// PersistActiveExchange writes one active-leg transcript and recovers the
// existing id on a retried (test_run_id, direction, request_id).
func (c *Core) PersistActiveExchange(ctx context.Context, draft ActiveExchangeDraft) (uint, error) {
	if c == nil || c.db == nil {
		return 0, errors.New("validatorcore: store is not configured")
	}

	row, err := reportExchangeFromDraft(draft)
	if err != nil {
		return 0, err
	}

	if err := c.InsertReportExchange(ctx, row); err != nil {
		if IsDuplicateReportExchange(err) {
			return c.recoverActiveExchangeID(ctx, row)
		}

		return 0, fmt.Errorf("validatorcore: persist %s exchange: %w", draft.EndpointID, err)
	}

	return row.ExchangeID, nil
}

// PersistActiveExchangeAndFact writes the transcript, then the sibling
// evidence_row carrying the persisted exchange id when the insert landed.
func (c *Core) PersistActiveExchangeAndFact(
	ctx context.Context,
	draft ActiveExchangeDraft,
	fact ApplyEvidenceFactInput,
) error {
	exchangeID, err := c.PersistActiveExchange(ctx, draft)
	if err != nil {
		return err
	}

	fact.ExchangeID = optionalExchangeID(exchangeID)

	if err := c.ApplyEvidenceFact(ctx, fact); err != nil {
		return fmt.Errorf("validatorcore: persist %s evidence: %w", fact.Area, err)
	}

	return nil
}

func reportExchangeFromDraft(draft ActiveExchangeDraft) (*ReportExchange, error) {
	if draft.TestRunID == "" {
		return nil, errors.New("validatorcore: empty test_run_id")
	}

	if _, ok := AreaForEndpoint(draft.EndpointID); !ok {
		return nil, errors.New("validatorcore: unknown active exchange endpoint")
	}

	if draft.Method == "" || draft.URL == "" || draft.Direction == "" || draft.RequestID == "" {
		return nil, errors.New("validatorcore: incomplete active exchange draft")
	}

	if !isKnownEvidenceLeg(draft.Leg) {
		return nil, errors.New("validatorcore: unknown evidence leg")
	}

	now := time.Now().Unix()
	reqID := draft.RequestID
	leg := draft.Leg
	actor := draft.Actor
	row := &ReportExchange{
		TestRunID:  draft.TestRunID,
		CapturedAt: now,
		Direction:  draft.Direction,
		EndpointID: draft.EndpointID,
		Method:     draft.Method,
		URL:        draft.URL,
		RequestID:  &reqID,
		Leg:        &leg,
		CreatedAt:  now,
	}

	if actor != "" {
		row.Actor = &actor
	}

	if draft.StatusCode > 0 {
		status := draft.StatusCode
		row.StatusCode = &status
	}

	return row, nil
}

func (c *Core) recoverActiveExchangeID(ctx context.Context, row *ReportExchange) (uint, error) {
	id, err := c.LookupReportExchangeID(ctx, row.TestRunID, row.Direction, requestIDOf(row))
	if err != nil {
		return 0, fmt.Errorf("validatorcore: recover %s exchange: %w", row.EndpointID, err)
	}

	return id, nil
}

func requestIDOf(row *ReportExchange) string {
	if row == nil || row.RequestID == nil {
		return ""
	}

	return *row.RequestID
}
