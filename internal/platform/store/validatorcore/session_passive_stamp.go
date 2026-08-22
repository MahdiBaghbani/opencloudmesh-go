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

const (
	colJwksURI        = "jwks_uri"
	colAPIVersion     = "api_version"
	colPassiveReadyAt = "passive_ready_at"
	reasonProbeFailed = "passive_probe_failed"
)

// StampPassiveProbeMetadata writes discovery-derived JWKS URI, platform, and
// API version onto the run. Empty values are left unchanged so nullable
// columns stay NULL and jwks_uri stays empty.
func (c *Core) StampPassiveProbeMetadata(
	ctx context.Context,
	testRunID, jwksURI, platform, apiVersion string,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()
	updates := map[string]any{
		colUpdatedAt: now,
	}

	if jwksURI != "" {
		updates[colJwksURI] = jwksURI
	}

	if platform != "" {
		updates[colPlatform] = platform
	}

	if apiVersion != "" {
		updates[colAPIVersion] = apiVersion
	}

	if len(updates) == 1 {
		return nil
	}

	if err := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", testRunID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("validatorcore: stamp passive probe metadata: %w", err)
	}

	return nil
}

// StampPassiveReadyAt records lock-wait readiness for an opt-in session that
// remains passive_running. A repeat stamp is a no-op.
func (c *Core) StampPassiveReadyAt(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where(
			"test_run_id = ? AND is_active = 0 AND state = ? AND opt_in_active = 1 AND passive_ready_at IS NULL",
			testRunID,
			StatePassiveRunning,
		).
		Updates(map[string]any{
			colPassiveReadyAt: now,
			colUpdatedAt:      now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: stamp passive ready at: %w", res.Error)
	}

	return nil
}

// FailPassive terminalizes a passive session from expectedState. The only
// supported expected state is passive_running.
func (c *Core) FailPassive(ctx context.Context, testRunID, expectedState, reason string) error {
	if expectedState != StatePassiveRunning {
		return fmt.Errorf("validatorcore: unsupported fail-passive state %q", expectedState)
	}

	if reason == "" {
		reason = reasonProbeFailed
	}

	return c.FailPassiveRunningTerminal(ctx, testRunID, reason)
}
