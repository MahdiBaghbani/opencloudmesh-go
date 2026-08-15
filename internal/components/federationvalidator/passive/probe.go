// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// ProbeRunner drives passive-core state transitions. Real federation conformance
// checks are not implemented in this wave; the insertion point below marks where
// the specification rater suite will run.
type ProbeRunner struct {
	store *validatorcore.Core
	log   *slog.Logger
}

// NewProbeRunner returns a passive probe runner bound to the validator store.
func NewProbeRunner(store *validatorcore.Core, log *slog.Logger) *ProbeRunner {
	return &ProbeRunner{
		store: store,
		log:   logutil.NoopIfNil(log),
	}
}

// StartAsync launches the passive probe for testRunID in a background goroutine.
func (p *ProbeRunner) StartAsync(ctx context.Context, testRunID string) {
	if p == nil || p.store == nil {
		return
	}

	go p.run(ctx, testRunID)
}

func (p *ProbeRunner) run(ctx context.Context, testRunID string) {
	if err := p.store.RunStartProbe(ctx, testRunID); err != nil {
		p.log.Warn("passive probe failed to start", "test_run_id", testRunID, "error", err)

		if failErr := p.store.FailRunTerminal(ctx, testRunID, "probe_start_failed"); failErr != nil {
			p.log.Warn("passive probe failed to terminalize after start miss", "test_run_id", testRunID, "error", failErr)
		}

		return
	}

	// INSERTION_POINT: run federation conformance checks and populate grades here.
	// This wave intentionally skips specification rater content; only state
	// transitions created -> passive_running -> passive_complete are wired.

	if err := p.store.CompletePassiveProbe(ctx, testRunID); err != nil {
		p.log.Warn("passive probe failed to complete", "test_run_id", testRunID, "error", err)

		if failErr := p.store.FailPassiveRunningTerminal(ctx, testRunID, "probe_complete_failed"); failErr != nil {
			p.log.Warn("passive probe failed to terminalize after complete miss", "test_run_id", testRunID, "error", failErr)
		}
	}
}
