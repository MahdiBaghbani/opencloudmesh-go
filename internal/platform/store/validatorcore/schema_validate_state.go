// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	gosqlite "github.com/glebarez/go-sqlite"
)

// stateProbeSavepoint wraps every state CHECK probe insert so the row is always rolled back and never persists.
const stateProbeSavepoint = "ocm_validator_state_probe"

// stateProbeCounter yields a fresh, unique sentinel primary key per probe
// insert, eliminating primary-key collisions as a class so the only insert
// failures left to classify are the state CHECK and unrelated errors.
var stateProbeCounter atomic.Uint64

// nextStateProbeID returns a probe-unique sentinel test_run primary key; every probe insert rolls back, so the row never persists and the id is never reused.
func nextStateProbeID() string {
	return fmt.Sprintf("__ocm_validator_state_probe_%d__", stateProbeCounter.Add(1))
}

// probeStateInsert inserts one test_run row whose only variable columns are the
// primary key and state; every other NOT NULL column gets a valid literal.
// checkTableShape has already confirmed the exact contract columns, so under a
// well-formed schema the state CHECK is the constraint this row exercises.
const probeStateInsert = `INSERT INTO test_run (
	test_run_id, is_active, state,
	target_origin, target_host, discovery_url,
	manifest_schema, created_at, updated_at
) VALUES (?, 0, ?, 'https://probe.invalid', 'probe.invalid',
	'https://probe.invalid/.well-known/ocm',
	'ocm-validator-manifest/v1', 0, 0)`

// unknownStateProbes are literals the live state CHECK must reject. They stand
// in for an over-broad constraint (a tautology tail, a typo, an empty value,
// or a retired live name): if any is admitted, the constraint is wider than
// the live state set.
var unknownStateProbes = []string{
	"",
	"RUNNING",
	"terminal_unknown",
	"zzz_not_a_state",
	"reverse_invite_solicited",
	"reverse_invite_imported",
}

// checkTestRunStateCheck verifies the enforced test_run.state CHECK by probing
// the live constraint instead of parsing stored DDL text: inside a savepoint
// that always rolls back, every live state must be accepted and every dormant
// or unexpected literal rejected. Because the probe tests what SQLite enforces,
// a broadened CHECK cannot change the result, so there is no SQL text to spoof.
func checkTestRunStateCheck(ctx context.Context, conn *sql.Conn) error {
	for _, state := range testRunStates {
		accepted, err := probeStateAccepted(ctx, conn, state)
		if err != nil {
			return err
		}

		if !accepted {
			return fmt.Errorf("validatorcore: schema: test_run state CHECK rejects required state %q", state)
		}
	}

	for _, state := range unknownStateProbes {
		if err := requireStateRejected(ctx, conn, state, "admits unexpected state"); err != nil {
			return err
		}
	}

	for _, state := range dormantTestRunStates {
		if err := requireStateRejected(ctx, conn, state, "admits dormant state"); err != nil {
			return err
		}
	}

	return checkTestRunStateCollation(ctx, conn)
}

// checkTestRunStateCollation proves the state CHECK matches state names under
// the SQLite default BINARY collation: a case variant and a trailing-space
// variant of a live state must both be rejected, since a NOCASE or RTRIM column
// would admit one and weaken the exact matching the CHECK and state index need.
func checkTestRunStateCollation(ctx context.Context, conn *sql.Conn) error {
	if len(testRunStates) == 0 {
		return nil
	}

	live := testRunStates[0]

	if caseVariant := strings.ToUpper(live); caseVariant != live {
		accepted, err := probeStateAccepted(ctx, conn, caseVariant)
		if err != nil {
			return err
		}

		if accepted {
			return fmt.Errorf(
				"validatorcore: schema: test_run.state matches case-insensitively (admits %q), want case-sensitive %s",
				caseVariant, testRunStateCollation,
			)
		}
	}

	spaceVariant := live + " "

	accepted, err := probeStateAccepted(ctx, conn, spaceVariant)
	if err != nil {
		return err
	}

	if accepted {
		return fmt.Errorf(
			"validatorcore: schema: test_run.state ignores trailing spaces (admits %q), want exact %s matching",
			spaceVariant, testRunStateCollation,
		)
	}

	return nil
}

// requireStateRejected fails closed when the live state CHECK admits state.
// admitted describes how the constraint is too broad for the error message.
func requireStateRejected(ctx context.Context, conn *sql.Conn, state, admitted string) error {
	accepted, err := probeStateAccepted(ctx, conn, state)
	if err != nil {
		return err
	}

	if accepted {
		return fmt.Errorf("validatorcore: schema: test_run state CHECK %s %q", admitted, state)
	}

	return nil
}

// sqliteConstraintCheck is SQLite's SQLITE_CONSTRAINT_CHECK extended result
// code, reported when an insert violates a CHECK constraint. The glebarez
// driver enables extended result codes, so a genuine CHECK rejection surfaces
// this exact code rather than the generic SQLITE_CONSTRAINT (19).
const sqliteConstraintCheck = 275

// isStateCheckRejection reports whether insertErr is a SQLite CHECK-constraint
// failure. State and non-state CHECK probes share this classifier: it is the
// only insert error meaning a CHECK refused the value. It relies solely on
// the driver's typed extended result code: any other error (PK, NOT NULL,
// UNIQUE, FK, trigger, infra, or a non-driver error whose text merely
// mentions a CHECK) is not a rejection and fails closed as a probe error.
func isStateCheckRejection(insertErr error) bool {
	var sqliteErr *gosqlite.Error
	if !errors.As(insertErr, &sqliteErr) {
		return false
	}

	return sqliteErr.Code() == sqliteConstraintCheck
}

// probeStateAccepted inserts a probe row (fresh unique primary key) inside a
// savepoint that always rolls back, then classifies the insert: no error is
// accepted (true); a CHECK-constraint failure is rejected (false); any other
// error is returned as a probe-infrastructure failure so validation fails closed.
func probeStateAccepted(ctx context.Context, conn *sql.Conn, state string) (bool, error) {
	if _, err := conn.ExecContext(ctx, "SAVEPOINT "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe savepoint: %w", err)
	}

	_, insertErr := conn.ExecContext(ctx, probeStateInsert, nextStateProbeID(), state)

	if _, err := conn.ExecContext(ctx, "ROLLBACK TO "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe rollback: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "RELEASE "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe release: %w", err)
	}

	if insertErr == nil {
		return true, nil
	}

	if isStateCheckRejection(insertErr) {
		return false, nil
	}

	return false, fmt.Errorf("validatorcore: schema: state probe failed: %w", insertErr)
}
