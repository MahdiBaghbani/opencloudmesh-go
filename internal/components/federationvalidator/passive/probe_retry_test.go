// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestProbeRunner_RetryExhaustionSettles(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("discovery returned status 500")

	tests := []struct {
		name        string
		runID       string
		optInActive bool
		result      *discovery.FetchResult
		err         error
		wantState   string
		wantReason  string
		wantReadyAt bool
	}{
		{
			name:  "discovery fail reaches terminal fail",
			runID: "run-exhaust-discovery-fail",
			result: &discovery.FetchResult{
				FetchErr: fetchErr,
				TLS:      validTLSState(),
				Headers:  http.Header{"Content-Type": []string{"text/plain"}},
			},
			err:        fetchErr,
			wantState:  validatorcore.StateTerminalFail,
			wantReason: failReasonProbeFailed,
		},
		{
			name:       "tls fail reaches terminal fail",
			runID:      "run-exhaust-tls-fail",
			result:     passingDiscoveryResult(expiredTLSState()),
			wantState:  validatorcore.StateTerminalFail,
			wantReason: failReasonProbeFailed,
		},
		{
			name:      "jwks fail opt-out reaches passive complete",
			runID:     "run-exhaust-jwks-opt-out",
			result:    advertisedFailingJWKSResult(),
			wantState: validatorcore.StatePassiveComplete,
		},
		{
			name:        "jwks fail opt-in stamps ready at",
			runID:       "run-exhaust-jwks-opt-in",
			optInActive: true,
			result:      advertisedFailingJWKSResult(),
			wantState:   validatorcore.StatePassiveRunning,
			wantReadyAt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			fetcher := &stubFetcher{result: tt.result, err: tt.err}
			runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})

			createCreatedRun(t, store, tt.runID, "https://peer.example", tt.optInActive, false)
			runner.run(t.Context(), tt.runID)

			got := mustGetRun(t, store, tt.runID)
			if got.State != tt.wantState {
				t.Fatalf("state = %q, want %q", got.State, tt.wantState)
			}

			if fetcher.calls != probeMaxAttempts {
				t.Fatalf("probe attempts = %d, want %d", fetcher.calls, probeMaxAttempts)
			}

			if tt.wantReason != "" && (got.TerminalReason == nil || *got.TerminalReason != tt.wantReason) {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, tt.wantReason)
			}

			if tt.wantReadyAt && (got.PassiveReadyAt == nil || *got.PassiveReadyAt <= 0) {
				t.Fatal("passive_ready_at must be stamped on opt-in exhaustion")
			}

			if !tt.wantReadyAt && got.PassiveReadyAt != nil {
				t.Fatal("passive_ready_at must stay unset outside opt-in lock-wait")
			}
		})
	}
}

func TestProbeRunner_PartialPersistRecoversExchangeID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	fetcher := &stubFetcher{result: passingDiscoveryResult(validTLSState())}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})
	ctx := t.Context()
	runID := "run-partial-persist"

	createCreatedRun(t, store, runID, "https://peer.example", false, false)

	bundle, err := runner.collectProbeBundle(ctx, runID)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if persistErr := runner.persistProbeBundle(ctx, runID, bundle); persistErr != nil {
		t.Fatalf("first persist: %v", persistErr)
	}

	var first validatorcore.ReportExchange
	if loadErr := store.DB().WithContext(ctx).
		Where("test_run_id = ? AND request_id = ?", runID, requestIDDiscovery).
		First(&first).Error; loadErr != nil {
		t.Fatalf("load first exchange: %v", loadErr)
	}

	if first.ExchangeID == 0 {
		t.Fatal("first persist must assign exchange id")
	}

	if delErr := store.DB().WithContext(ctx).
		Where("test_run_id = ?", runID).
		Delete(&validatorcore.EvidenceRow{}).Error; delErr != nil {
		t.Fatalf("delete evidence: %v", delErr)
	}

	if persistErr := runner.persistProbeBundle(ctx, runID, bundle); persistErr != nil {
		t.Fatalf("retry persist: %v", persistErr)
	}

	var ev validatorcore.EvidenceRow
	if loadErr := store.DB().WithContext(ctx).
		Where("test_run_id = ? AND area = ?", runID, validatorcore.SpecificationAreaDiscovery).
		First(&ev).Error; loadErr != nil {
		t.Fatalf("load discovery evidence: %v", loadErr)
	}

	if ev.ExchangeID == nil || *ev.ExchangeID != first.ExchangeID {
		t.Fatalf("evidence exchange_id = %v, want %d", ev.ExchangeID, first.ExchangeID)
	}

	assertExchangeCount(t, store, runID, exchangeDiscoveryID, 1)
}

func TestProbeRunner_RetryLastWinsAreaGrade(t *testing.T) {
	t.Parallel()

	t.Run("jwks fail then pass overwrites", func(t *testing.T) {
		t.Parallel()

		var fetches atomic.Int32

		jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if fetches.Add(1) == 1 {
				http.Error(w, "jwks unavailable", http.StatusBadGateway)

				return
			}

			w.Header().Set("Content-Type", "application/json")
			writeJWKSBody(t, w)
		}))
		t.Cleanup(jwksServer.Close)

		result := passingDiscoveryResult(validTLSState())
		result.Discovery.JwksUri = jwksServer.URL

		store := openHandlerTestStore(t)
		runID := "run-last-wins-jwks"
		runner := NewProbeRunnerWithDeps(ProbeDeps{
			Store:     store,
			Discovery: &stubFetcher{result: result},
			HTTP:      httpclient.NewContextClient(tlsTestClient()),
		})

		createCreatedRun(t, store, runID, "https://peer.example", false, true)
		runner.run(t.Context(), runID)

		got := mustGetRun(t, store, runID)
		if got.State != validatorcore.StatePassiveComplete {
			t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
		}

		if fetches.Load() < 2 {
			t.Fatalf("jwks fetches = %d, want at least 2", fetches.Load())
		}

		assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaJWKS)
		assertAreaSeverity(t, store, runID, validatorcore.SpecificationAreaJWKS, validatorcore.GradePass)
		assertRatedAreaGrade(t, store, runID, validatorcore.SpecificationAreaJWKS, validatorcore.GradePass)
		assertEvidenceUsesLatestExchange(t, store, runID, validatorcore.SpecificationAreaJWKS, exchangeJWKSID)

		if err := store.StopPassiveComplete(t.Context(), runID); err != nil {
			t.Fatalf("StopPassiveComplete: %v", err)
		}

		assertStatsJWKSGrade(t, store, validatorcore.GradePass)
	})

	t.Run("final discovery fail still terminalizes", func(t *testing.T) {
		t.Parallel()

		fetchErr := errors.New("discovery returned status 500")
		store := openHandlerTestStore(t)
		fetcher := &stubFetcher{
			result: &discovery.FetchResult{
				FetchErr: fetchErr,
				TLS:      validTLSState(),
				Headers:  http.Header{"Content-Type": []string{"text/plain"}},
			},
			err: fetchErr,
		}
		runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})
		runID := "run-last-wins-discovery-fail"

		createCreatedRun(t, store, runID, "https://peer.example", false, true)
		runner.run(t.Context(), runID)

		got := mustGetRun(t, store, runID)
		if got.State != validatorcore.StateTerminalFail {
			t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
		}

		if got.TerminalReason == nil || *got.TerminalReason != failReasonProbeFailed {
			t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, failReasonProbeFailed)
		}

		if fetcher.calls != probeMaxAttempts {
			t.Fatalf("probe attempts = %d, want %d", fetcher.calls, probeMaxAttempts)
		}

		assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaDiscovery)
		assertAreaSeverity(t, store, runID, validatorcore.SpecificationAreaDiscovery, validatorcore.GradeFail)
		assertStatsDiscoveryGrade(t, store, runID, validatorcore.GradeFail)
	})

	t.Run("httpsig fail then pass overwrites", func(t *testing.T) {
		t.Parallel()

		var probes atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/ocm-httpsig-probe" {
				http.NotFound(w, r)

				return
			}

			n := probes.Add(1)
			if n <= 2 {
				http.NotFound(w, r)

				return
			}

			if strings.HasSuffix(r.Header.Get("Signature"), "x") {
				w.WriteHeader(http.StatusUnauthorized)

				return
			}

			http.NotFound(w, r)
		}))
		t.Cleanup(server.Close)

		store := openHandlerTestStore(t)
		runID := "run-last-wins-httpsig"
		runner := NewProbeRunnerWithDeps(ProbeDeps{
			Store:     store,
			Discovery: &stubFetcher{result: passingDiscoveryResult(validTLSState())},
			HTTP:      httpclient.NewContextClient(tlsTestClient()),
			Signer:    newIntegrationSigner(t),
		})

		createCreatedRun(t, store, runID, server.URL, false, true)
		runner.run(t.Context(), runID)

		got := mustGetRun(t, store, runID)
		if got.State != validatorcore.StatePassiveComplete {
			t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
		}

		if probes.Load() < 4 {
			t.Fatalf("httpsig probes = %d, want at least 4", probes.Load())
		}

		assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaHTTPSig)
		assertAreaSeverity(t, store, runID, validatorcore.SpecificationAreaHTTPSig, validatorcore.GradePass)
		assertRatedAreaGrade(t, store, runID, validatorcore.SpecificationAreaHTTPSig, validatorcore.GradePass)
		assertEvidenceUsesLatestRequest(t, store, runID, validatorcore.SpecificationAreaHTTPSig, requestIDHTTPSig)
		assertHTTPSigTamperedPersisted(t, store, runID)
	})
}

func TestProbeRunner_CancelledRetryWaitStillSettles(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("discovery returned status 500")

	tests := []struct {
		name        string
		runID       string
		optInActive bool
		result      *discovery.FetchResult
		err         error
		wantState   string
		wantReason  string
		wantReadyAt bool
	}{
		{
			name:  "cancelled wait still terminal fails on discovery",
			runID: "run-cancel-discovery-fail",
			result: &discovery.FetchResult{
				FetchErr: fetchErr,
				TLS:      validTLSState(),
				Headers:  http.Header{"Content-Type": []string{"text/plain"}},
			},
			err:        fetchErr,
			wantState:  validatorcore.StateTerminalFail,
			wantReason: failReasonProbeFailed,
		},
		{
			name:      "cancelled wait still completes on jwks fail",
			runID:     "run-cancel-jwks-opt-out",
			result:    advertisedFailingJWKSResult(),
			wantState: validatorcore.StatePassiveComplete,
		},
		{
			name:        "cancelled wait still stamps lock-wait ready at",
			runID:       "run-cancel-jwks-opt-in",
			optInActive: true,
			result:      advertisedFailingJWKSResult(),
			wantState:   validatorcore.StatePassiveRunning,
			wantReadyAt: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			store := openHandlerTestStore(t)
			fetcher := &cancelOnFetchFetcher{
				result: tt.result,
				err:    tt.err,
				cancel: cancel,
			}
			runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})

			createCreatedRun(t, store, tt.runID, "https://peer.example", tt.optInActive, false)
			runner.run(ctx, tt.runID)

			got := mustGetRun(t, store, tt.runID)
			if got.State != tt.wantState {
				t.Fatalf("state = %q, want %q after cancelled retry wait", got.State, tt.wantState)
			}

			if fetcher.calls != 1 {
				t.Fatalf("probe attempts = %d, want 1 (retry wait cancelled)", fetcher.calls)
			}

			if tt.wantReason != "" && (got.TerminalReason == nil || *got.TerminalReason != tt.wantReason) {
				t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, tt.wantReason)
			}

			if tt.wantReadyAt && (got.PassiveReadyAt == nil || *got.PassiveReadyAt <= 0) {
				t.Fatal("passive_ready_at must be stamped when cancelled wait settles to lock-wait")
			}

			if !tt.wantReadyAt && got.PassiveReadyAt != nil {
				t.Fatal("passive_ready_at must stay unset outside opt-in lock-wait")
			}
		})
	}
}

type cancelOnFetchFetcher struct {
	result *discovery.FetchResult
	err    error
	cancel context.CancelFunc
	calls  int
}

func (s *cancelOnFetchFetcher) FetchFresh(_ context.Context, _ string) (*discovery.FetchResult, error) {
	s.calls++
	if s.calls == 1 && s.cancel != nil {
		s.cancel()
	}

	return s.result, s.err
}

func writeJWKSBody(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	if _, err := io.WriteString(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"YQ"}]}`); err != nil {
		t.Errorf("write jwks body: %v", err)
	}
}

func assertRatedAreaGrade(t *testing.T, store *validatorcore.Core, runID, area, want string) {
	t.Helper()

	run := mustGetRun(t, store, runID)

	score, _, err := store.LoadSpecificationRating(t.Context(), run)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	for _, item := range score.Areas {
		if item.Area != area {
			continue
		}

		if item.Grade == nil || *item.Grade != want {
			t.Fatalf("%s rated grade = %v, want %q", area, item.Grade, want)
		}

		return
	}

	t.Fatalf("area %q missing from specification rating", area)
}

func assertStatsJWKSGrade(t *testing.T, store *validatorcore.Core, want string) {
	t.Helper()

	var raw validatorcore.StatsRaw
	if err := store.DB().WithContext(t.Context()).
		Where("host_hash != ''").
		First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeJWKS == nil || *raw.GradeJWKS != want {
		t.Fatalf("stats grade_jwks = %v, want %q", raw.GradeJWKS, want)
	}
}

func assertHTTPSigTamperedPersisted(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	var n int64
	if err := store.DB().WithContext(t.Context()).
		Model(&validatorcore.ReportExchange{}).
		Where("test_run_id = ? AND request_id LIKE ?", runID, requestIDHTTPSigTampered+"%").
		Count(&n).Error; err != nil {
		t.Fatalf("count tampered httpsig exchanges: %v", err)
	}

	if n < 2 {
		t.Fatalf("tampered httpsig exchanges = %d, want at least 2", n)
	}
}

func advertisedFailingJWKSResult() *discovery.FetchResult {
	result := passingDiscoveryResult(validTLSState())
	result.Discovery.JwksUri = "https://peer.example/jwks.json"
	result.Discovery.Capabilities = []string{spec.CapabilityHTTPSig}

	return result
}
