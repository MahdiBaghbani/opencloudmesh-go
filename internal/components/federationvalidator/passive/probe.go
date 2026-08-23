// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	probeMaxAttempts      = 3
	probeRetryWait        = 50 * time.Millisecond
	failReasonStartFailed = "probe_start_failed"
	failReasonProbeFailed = "passive_probe_failed"
)

var (
	errProbeSettled    = errors.New("passive probe already settled")
	errRetryable       = errors.New("passive probe retryable")
	errProbeIncomplete = errors.New("passive probe incomplete")
)

// DiscoveryFetcher performs a cache-bypassing OCM discovery fetch for passive probes.
type DiscoveryFetcher interface {
	FetchFresh(ctx context.Context, baseURL string) (*discovery.FetchResult, error)
}

// ActiveKicker is the wake-only seam for a future active runner.
// Kick is a buffered signal with no arguments. A nil kicker is a no-op
// so an unbound runner never panics.
type ActiveKicker interface {
	Kick()
}

// ProbeDeps wires store, discovery, HTTP, signing, and the optional active
// wake-up seam into the passive runner.
type ProbeDeps struct {
	Store      *validatorcore.Core
	Discovery  DiscoveryFetcher
	HTTP       *httpclient.ContextClient
	Signer     *crypto.RFC9421Signer
	Log        *slog.Logger
	ActiveKick ActiveKicker
}

// ProbeRunner drives passive-core state transitions and records four-area
// discovery, TLS, JWKS, and HTTPSig evidence on the persisted test run.
type ProbeRunner struct {
	store     *validatorcore.Core
	discovery DiscoveryFetcher
	http      *httpclient.ContextClient
	signer    *crypto.RFC9421Signer
	log       *slog.Logger
	kick      ActiveKicker
}

// NewProbeRunner returns a passive probe runner bound to the validator store.
func NewProbeRunner(store *validatorcore.Core, log *slog.Logger) *ProbeRunner {
	return NewProbeRunnerWithDeps(ProbeDeps{Store: store, Log: log})
}

// NewProbeRunnerWithDiscovery returns a probe runner with optional discovery fetch wiring.
func NewProbeRunnerWithDiscovery(
	store *validatorcore.Core,
	discoveryClient DiscoveryFetcher,
	log *slog.Logger,
) *ProbeRunner {
	return NewProbeRunnerWithDeps(ProbeDeps{
		Store:     store,
		Discovery: discoveryClient,
		Log:       log,
	})
}

// NewProbeRunnerWithDeps returns a probe runner from the full dependency set.
func NewProbeRunnerWithDeps(deps ProbeDeps) *ProbeRunner {
	return &ProbeRunner{
		store:     deps.Store,
		discovery: deps.Discovery,
		http:      deps.HTTP,
		signer:    deps.Signer,
		log:       logutil.NoopIfNil(deps.Log),
		kick:      deps.ActiveKick,
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
	var last *probeBundle

	attempt := 0

	err := retryBounded(ctx, func() error {
		attempt++

		bundle, runErr := p.runOnce(ctx, testRunID, attempt)
		if bundle != nil {
			last = bundle
		}

		if errors.Is(runErr, errProbeSettled) {
			return nil
		}

		return runErr
	})
	if err == nil {
		return
	}

	p.log.Warn("passive probe stopped", "test_run_id", testRunID, "error", err)
	p.settleExhaustedProbe(context.WithoutCancel(ctx), testRunID, last)
}

func (p *ProbeRunner) runOnce(ctx context.Context, testRunID string, attempt int) (*probeBundle, error) {
	if err := p.ensureProbeStarted(ctx, testRunID); err != nil {
		return nil, err
	}

	if p.discovery == nil {
		return nil, p.completeOrWait(ctx, testRunID)
	}

	return p.probeAndPersist(ctx, testRunID, attempt)
}

func (p *ProbeRunner) probeAndPersist(
	ctx context.Context,
	testRunID string,
	attempt int,
) (*probeBundle, error) {
	bundle, err := p.collectProbeBundle(ctx, testRunID)
	if err != nil {
		return nil, err
	}

	bundle.attempt = attempt

	if persistErr := p.persistProbeBundle(ctx, testRunID, bundle); persistErr != nil {
		return &bundle, wrapRetryable(persistErr)
	}

	if needsAnotherAttempt(bundle.grades) {
		return &bundle, wrapRetryable(errProbeIncomplete)
	}

	return &bundle, p.completeOrWait(ctx, testRunID)
}

func (p *ProbeRunner) settleExhaustedProbe(ctx context.Context, testRunID string, last *probeBundle) {
	if !p.shouldSettleExhausted(ctx, testRunID) {
		return
	}

	if last != nil {
		if persistErr := retryStoreOp(ctx, func() error {
			return p.persistProbeBundle(ctx, testRunID, *last)
		}); persistErr != nil {
			p.log.Warn("passive probe exhausted persist failed", "test_run_id", testRunID, "error", persistErr)

			return
		}
	}

	if settleErr := retryStoreOp(ctx, func() error {
		return p.finishExhaustedProbe(ctx, testRunID, last)
	}); settleErr != nil {
		p.log.Warn("passive probe exhausted settlement failed", "test_run_id", testRunID, "error", settleErr)
	}
}

func (p *ProbeRunner) shouldSettleExhausted(ctx context.Context, testRunID string) bool {
	row, err := p.store.GetTestRun(ctx, testRunID)
	if err != nil {
		p.log.Warn("passive probe exhausted load failed", "test_run_id", testRunID, "error", err)

		return true
	}

	return row.State == validatorcore.StatePassiveRunning
}

func (p *ProbeRunner) finishExhaustedProbe(ctx context.Context, testRunID string, last *probeBundle) error {
	if last == nil || isFailGate(last.grades) {
		return p.failPassiveProbe(ctx, testRunID)
	}

	return p.completeOrWait(ctx, testRunID)
}

func (p *ProbeRunner) ensureProbeStarted(ctx context.Context, testRunID string) error {
	startErr := p.store.RunStartProbe(ctx, testRunID)
	if startErr == nil {
		return nil
	}

	row, getErr := p.store.GetTestRun(ctx, testRunID)
	if getErr != nil {
		return wrapRetryable(fmt.Errorf("passive probe start: %w", getErr))
	}

	switch row.State {
	case validatorcore.StatePassiveRunning:
		return nil
	case validatorcore.StatePassiveComplete,
		validatorcore.StateActiveRunning,
		validatorcore.StateTerminalPass,
		validatorcore.StateTerminalFail,
		validatorcore.StateInterrupted:
		return errProbeSettled
	case validatorcore.StateCreated:
		return wrapRetryable(fmt.Errorf("passive probe start: %w", startErr))
	default:
		p.failCreated(ctx, testRunID)

		return fmt.Errorf("passive probe start: unexpected state %q", row.State)
	}
}

func (p *ProbeRunner) failCreated(ctx context.Context, testRunID string) {
	if failErr := p.store.FailRunTerminal(ctx, testRunID, failReasonStartFailed); failErr != nil {
		p.log.Warn("passive probe failed to terminalize after start miss", "test_run_id", testRunID, "error", failErr)
	}
}

func (p *ProbeRunner) failPassiveProbe(ctx context.Context, testRunID string) error {
	if err := p.store.FailPassive(ctx, testRunID, validatorcore.StatePassiveRunning, failReasonProbeFailed); err != nil {
		return wrapRetryable(err)
	}

	return nil
}

func (p *ProbeRunner) completeOrWait(ctx context.Context, testRunID string) error {
	row, err := p.store.GetTestRun(ctx, testRunID)
	if err != nil {
		return wrapRetryable(err)
	}

	if row.OptInActive {
		if promoErr := p.promoteOrWait(ctx, testRunID); promoErr != nil {
			return wrapRetryable(promoErr)
		}

		return nil
	}

	if err := p.store.CompletePassiveProbe(ctx, testRunID); err != nil {
		if failErr := p.store.FailPassiveRunningTerminal(ctx, testRunID, "probe_complete_failed"); failErr != nil {
			p.log.Warn("passive probe failed to terminalize after complete miss", "test_run_id", testRunID, "error", failErr)
		}

		return wrapRetryable(err)
	}

	return nil
}

func retryBounded(ctx context.Context, fn func() error) error {
	var err error

	for attempt := range probeMaxAttempts {
		err = fn()
		if err == nil || !isRetryable(err) {
			return err
		}

		if attempt == probeMaxAttempts-1 {
			return err
		}

		if waitErr := waitRetry(ctx); waitErr != nil {
			return waitErr
		}
	}

	return err
}

func waitRetry(ctx context.Context) error {
	timer := time.NewTimer(probeRetryWait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("passive probe retry: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func retryStoreOp(ctx context.Context, fn func() error) error {
	return retryBounded(ctx, func() error {
		err := fn()
		if err == nil || isRetryable(err) {
			return err
		}

		return wrapRetryable(err)
	})
}

func wrapRetryable(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%w: %w", errRetryable, err)
}

func isRetryable(err error) bool {
	return errors.Is(err, errRetryable)
}

func isFailGrade(grade *string) bool {
	return grade != nil && *grade == validatorcore.GradeFail
}

func isFailGate(grades areaGrades) bool {
	return isFailGrade(grades.discovery) || isFailGrade(grades.tls)
}

func needsAnotherAttempt(grades areaGrades) bool {
	return isFailGate(grades) || isFailGrade(grades.jwks) || isFailGrade(grades.httpsig)
}
