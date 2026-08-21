// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/platformdetect"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/tlsprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// DiscoveryFetcher performs a cache-bypassing OCM discovery fetch for passive probes.
type DiscoveryFetcher interface {
	FetchFresh(ctx context.Context, baseURL string) (*discovery.FetchResult, error)
}

// ProbeRunner drives passive-core state transitions and records discovery-derived
// platform, API version, and TLS grades on the persisted test run and evidence.
type ProbeRunner struct {
	store     *validatorcore.Core
	discovery DiscoveryFetcher
	log       *slog.Logger
}

// NewProbeRunner returns a passive probe runner bound to the validator store.
func NewProbeRunner(store *validatorcore.Core, log *slog.Logger) *ProbeRunner {
	return NewProbeRunnerWithDiscovery(store, nil, log)
}

// NewProbeRunnerWithDiscovery returns a probe runner with optional discovery fetch wiring.
func NewProbeRunnerWithDiscovery(
	store *validatorcore.Core,
	discoveryClient DiscoveryFetcher,
	log *slog.Logger,
) *ProbeRunner {
	return &ProbeRunner{
		store:     store,
		discovery: discoveryClient,
		log:       logutil.NoopIfNil(log),
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

	if facts, ok := p.collectPassiveProbeFacts(ctx, testRunID); ok {
		if recErr := p.store.RecordPassiveProbeFacts(
			ctx,
			testRunID,
			facts.platform,
			facts.apiVersion,
			facts.tlsGrade,
		); recErr != nil {
			p.log.Warn("passive probe failed to persist facts", "test_run_id", testRunID, "error", recErr)
		}
	}

	if err := p.store.CompletePassiveProbe(ctx, testRunID); err != nil {
		p.log.Warn("passive probe failed to complete", "test_run_id", testRunID, "error", err)

		if failErr := p.store.FailPassiveRunningTerminal(ctx, testRunID, "probe_complete_failed"); failErr != nil {
			p.log.Warn("passive probe failed to terminalize after complete miss", "test_run_id", testRunID, "error", failErr)
		}
	}
}

type passiveProbeFacts struct {
	platform   string
	apiVersion string
	tlsGrade   *string
}

func (p *ProbeRunner) collectPassiveProbeFacts(ctx context.Context, testRunID string) (passiveProbeFacts, bool) {
	if p.discovery == nil {
		return passiveProbeFacts{}, false
	}

	row, err := p.store.GetTestRun(ctx, testRunID)
	if err != nil {
		p.log.Warn("passive probe could not load session", "test_run_id", testRunID, "error", err)

		return passiveProbeFacts{}, false
	}

	result, fetchErr := p.discovery.FetchFresh(ctx, row.TargetOrigin)

	effectiveFetchErr := fetchErr
	if result != nil && result.FetchErr != nil {
		effectiveFetchErr = result.FetchErr
	}

	if effectiveFetchErr != nil {
		p.log.Warn(
			"passive probe discovery fetch failed",
			"test_run_id", testRunID,
			"target_origin", row.TargetOrigin,
			"error", effectiveFetchErr,
		)
	}

	scheme := tlsprobe.SchemeFromURL(row.TargetOrigin)

	var provider string

	var headers http.Header

	var apiVersion string

	if result != nil {
		headers = result.Headers
		if result.Discovery != nil {
			provider = result.Discovery.Provider
			apiVersion = result.Discovery.APIVersion
		}
	}

	if headers == nil {
		headers = make(map[string][]string)
	}

	tlsInput := tlsprobe.Input{
		Scheme:   scheme,
		ServerIP: "",
		FetchErr: effectiveFetchErr,
	}

	if result != nil {
		tlsInput.TLSState = result.TLS
		tlsInput.ServerIP = result.ServerIP
	}

	detail := tlsprobe.CaptureTLS(tlsInput)

	return passiveProbeFacts{
		platform:   platformdetect.Detect(provider, headers),
		apiVersion: apiVersion,
		tlsGrade:   tlsprobe.GradeTLS(detail, scheme, effectiveFetchErr),
	}, true
}
