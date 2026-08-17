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
// platform and TLS grades on the terminal stats snapshot overlay.
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

	if overlay, ok := p.buildTerminalOverlay(ctx, testRunID); ok {
		p.store.SetTerminalStatsSnapshot(testRunID, overlay)
	}

	if err := p.store.CompletePassiveProbe(ctx, testRunID); err != nil {
		p.log.Warn("passive probe failed to complete", "test_run_id", testRunID, "error", err)

		if failErr := p.store.FailPassiveRunningTerminal(ctx, testRunID, "probe_complete_failed"); failErr != nil {
			p.log.Warn("passive probe failed to terminalize after complete miss", "test_run_id", testRunID, "error", failErr)
		}
	}
}

func (p *ProbeRunner) buildTerminalOverlay(ctx context.Context, testRunID string) (validatorcore.StatsSnapshot, bool) {
	if p.discovery == nil {
		return validatorcore.StatsSnapshot{}, false
	}

	row, err := p.store.GetTestRun(ctx, testRunID)
	if err != nil {
		p.log.Warn("passive probe could not load session", "test_run_id", testRunID, "error", err)

		return validatorcore.StatsSnapshot{}, false
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

	overlay := validatorcore.StatsSnapshot{
		Platform:   platformdetect.Detect(provider, headers),
		APIVersion: apiVersion,
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
	report := tlsprobe.ConnectionReport(detail)
	overlay.ConnectionReport = &report
	overlay.GradeTLS = tlsprobe.GradeTLS(detail, scheme, effectiveFetchErr)

	return overlay, true
}
