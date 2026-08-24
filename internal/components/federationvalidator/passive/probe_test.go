// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type stubFetcher struct {
	result *discovery.FetchResult
	err    error
	calls  int
}

func (s *stubFetcher) FetchFresh(_ context.Context, _ string) (*discovery.FetchResult, error) {
	s.calls++

	return s.result, s.err
}

func TestProbeRunner_ReachesPassiveComplete(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	runner := NewProbeRunner(store, nil)
	ctx := t.Context()
	runID := "run-async-probe"

	createCreatedRun(t, store, runID, "https://probe.example", false, false)
	runner.run(ctx, runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
	}
}

func TestProbeRunner_PromotesOptInWhenSlotFree(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	kicker := &recordKicker{}
	h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
	allowActiveExtend(h)
	h.SetReverseReceiver(
		identity.NewMemoryPartyRepo(),
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	ctx := t.Context()
	runID := "run-promote-free"

	createCreatedRun(t, store, runID, "https://probe.example", true, false)
	h.probe.run(ctx, runID)

	got := mustGetRun(t, store, runID)
	if !got.IsActive || got.State != validatorcore.StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", got.IsActive, got.State)
	}

	if got.BobUserID == nil || *got.BobUserID == "" {
		t.Fatal("bob_user_id must be minted on promotion")
	}

	if kicker.calls != 1 {
		t.Fatalf("kick calls = %d, want 1", kicker.calls)
	}
}

func TestProbeRunner_OptInWithoutCapsFailsClosed(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	kicker := &recordKicker{}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
	runID := "run-opt-in-no-caps"

	createCreatedRun(t, store, runID, "https://probe.example", true, false)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonActiveUnavailable {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonActiveUnavailable)
	}

	if got.IsActive {
		t.Fatal("unavailable active opt-in must not take the active lock")
	}

	if kicker.calls != 0 {
		t.Fatalf("kick calls = %d, want none", kicker.calls)
	}
}

func TestProbeRunner_LockWaitStampsReadyAt(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	kicker := &recordKicker{}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
	allowProbeExtend(runner)

	ctx := t.Context()
	runID := "run-lock-wait"

	seedActiveHolder(t, store, "run-lock-holder")
	createCreatedRun(t, store, runID, "https://probe.example", true, false)
	runner.run(ctx, runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StatePassiveRunning {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveRunning)
	}

	if got.PassiveReadyAt == nil || *got.PassiveReadyAt <= 0 {
		t.Fatal("passive_ready_at must be stamped on lock-wait")
	}

	if got.IsActive {
		t.Fatal("lock-wait must not take the active lock")
	}

	if kicker.calls != 0 {
		t.Fatalf("kick calls = %d, want none on lock-wait", kicker.calls)
	}
}

func TestProbeRunner_FailedDiscoveryNeverPromotesOptIn(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	fetchErr := errors.New("discovery returned status 500")
	fetcher := &stubFetcher{
		result: &discovery.FetchResult{
			FetchErr: fetchErr,
			TLS:      validTLSState(),
			Headers:  http.Header{"Content-Type": []string{"text/plain"}},
		},
		err: fetchErr,
	}
	kicker := &recordKicker{}
	runner := NewProbeRunnerWithDeps(ProbeDeps{
		Store:      store,
		Discovery:  fetcher,
		ActiveKick: kicker,
	})
	runID := "run-opt-in-discovery-fail"

	createCreatedRun(t, store, runID, "https://peer.example", true, false)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	if got.IsActive {
		t.Fatal("failed probe must not take the active lock")
	}

	if kicker.calls != 0 {
		t.Fatalf("kick calls = %d, want none after failed probe", kicker.calls)
	}
}

func TestProbeRunner_DiscoveryFailGatesWithoutComplete(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	fetchErr := errors.New("discovery returned status 500")
	fetcher := &stubFetcher{
		result: &discovery.FetchResult{
			FetchErr: fetchErr,
			TLS:      validTLSState(),
			Headers:  http.Header{"Content-Type": []string{"text/plain"}},
		},
		err: fetchErr,
	}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher, Log: nil})
	runID := "run-discovery-fail"

	createCreatedRun(t, store, runID, "https://peer.example", false, true)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonPassiveProbeFailed {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonPassiveProbeFailed)
	}

	assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaDiscovery)
	assertStatsDiscoveryGrade(t, store, runID, validatorcore.GradeFail)
}

func TestProbeRunner_TLSFailGatesWhenDiscoveryPasses(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	fetcher := &stubFetcher{result: passingDiscoveryResult(expiredTLSState())}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})
	runID := "run-tls-fail"

	createCreatedRun(t, store, runID, "https://peer.example", false, false)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaTLS)
	assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaDiscovery)
}

func TestProbeRunner_BadJWKSAndHTTPSigStillComplete(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	result := passingDiscoveryResult(validTLSState())
	result.Discovery.JwksUri = "https://peer.example/jwks.json"
	result.Discovery.Capabilities = []string{spec.CapabilityHTTPSig}

	fetcher := &stubFetcher{result: result}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})
	runID := "run-soft-fail-complete"

	createCreatedRun(t, store, runID, "https://peer.example", false, false)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
	}

	if got.JwksURI != "https://peer.example/jwks.json" {
		t.Fatalf("jwks_uri = %q, want advertised uri", got.JwksURI)
	}

	if got.APIVersion == nil || *got.APIVersion != "1.4.0" {
		t.Fatalf("api_version = %v, want 1.4.0", got.APIVersion)
	}

	assertAreaSeverity(t, store, runID, validatorcore.SpecificationAreaJWKS, validatorcore.GradeFail)
	assertAreaSeverity(t, store, runID, validatorcore.SpecificationAreaHTTPSig, validatorcore.GradeFail)
}

func TestProbeRunner_RetryDoesNotDuplicateEvidence(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	fetcher := &stubFetcher{result: passingDiscoveryResult(validTLSState())}
	runner := NewProbeRunnerWithDeps(ProbeDeps{Store: store, Discovery: fetcher})
	runID := "run-retry-idempotent"

	createCreatedRun(t, store, runID, "https://peer.example", false, false)
	runner.run(t.Context(), runID)
	runner.run(t.Context(), runID)

	got := mustGetRun(t, store, runID)
	if got.State != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
	}

	assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaDiscovery)
	assertExchangeCount(t, store, runID, exchangeDiscoveryID, probeMaxAttempts)
}

func TestRetryBounded_RetriesThenSucceeds(t *testing.T) {
	t.Parallel()

	calls := 0

	err := retryBounded(t.Context(), func() error {
		calls++
		if calls < probeMaxAttempts {
			return wrapRetryable(errors.New("transient persist"))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("retryBounded: %v", err)
	}

	if calls != probeMaxAttempts {
		t.Fatalf("calls = %d, want %d", calls, probeMaxAttempts)
	}
}

func TestOverlaySymbolsRemoved(t *testing.T) {
	t.Parallel()

	src := probeSourceFiles(t)
	for _, token := range []string{"buildTerminalOverlay", "SetTerminalStatsSnapshot"} {
		if strings.Contains(src, token) {
			t.Fatalf("stale overlay symbol %q must not remain", token)
		}
	}
}

func passingDiscoveryResult(tlsState *tls.ConnectionState) *discovery.FetchResult {
	return &discovery.FetchResult{
		Discovery: &spec.Discovery{
			Enabled:    true,
			APIVersion: "1.4.0",
			EndPoint:   "https://peer.example/ocm",
			Provider:   "Nextcloud 28",
		},
		Raw:     []byte(`{"enabled":true,"apiVersion":"1.4.0"}`),
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		TLS:     tlsState,
	}
}

func validTLSState() *tls.ConnectionState {
	return tlsStateForWindow(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func expiredTLSState() *tls.ConnectionState {
	return tlsStateForWindow(time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
}

func tlsStateForWindow(notBefore, notAfter time.Time) *tls.ConnectionState {
	cert := &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Subject:   pkix.Name{CommonName: "peer.example"},
	}

	return &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{cert},
	}
}

type recordKicker struct {
	calls int
}

func (r *recordKicker) Kick() {
	r.calls++
}

func seedActiveHolder(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	now := time.Now().Unix()
	row := &validatorcore.TestRun{
		TestRunID:  runID,
		IsActive:   true,
		State:      validatorcore.StateActiveRunning,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed holder: %v", err)
	}
}

func createCreatedRun(
	t *testing.T,
	store *validatorcore.Core,
	runID, origin string,
	optInActive, optInStats bool,
) {
	t.Helper()

	now := time.Now().Unix()
	row := &validatorcore.TestRun{
		TestRunID:    runID,
		State:        validatorcore.StateCreated,
		TargetOrigin: origin,
		TargetHost:   "peer.example",
		DiscoveryURL: strings.TrimSuffix(origin, "/") + "/.well-known/ocm",
		OptInActive:  optInActive,
		OptInStats:   optInStats,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := store.CreatePassiveSession(t.Context(), row); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func mustGetRun(t *testing.T, store *validatorcore.Core, runID string) *validatorcore.TestRun {
	t.Helper()

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return got
}

func assertOneEvidenceArea(t *testing.T, store *validatorcore.Core, runID, area string) {
	t.Helper()

	var n int64
	if err := store.DB().WithContext(t.Context()).
		Model(&validatorcore.EvidenceRow{}).
		Where("test_run_id = ? AND area = ?", runID, area).
		Count(&n).Error; err != nil {
		t.Fatalf("count %s evidence: %v", area, err)
	}

	if n != 1 {
		t.Fatalf("%s evidence rows = %d, want 1", area, n)
	}
}

func assertAreaSeverity(t *testing.T, store *validatorcore.Core, runID, area, want string) {
	t.Helper()

	var row validatorcore.EvidenceRow
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ?", runID, area).
		First(&row).Error; err != nil {
		t.Fatalf("load %s evidence: %v", area, err)
	}

	if row.Severity != want || !row.AffectsGrade {
		t.Fatalf("%s evidence severity=%q affects=%v, want %q/true", area, row.Severity, row.AffectsGrade, want)
	}

	if row.Leg == nil || *row.Leg != validatorcore.EvidenceLegPassive {
		t.Fatalf("%s evidence leg = %v, want passive", area, row.Leg)
	}
}

func assertExchangeCount(t *testing.T, store *validatorcore.Core, runID, endpointID string, want int) {
	t.Helper()

	var n int64
	if err := store.DB().WithContext(t.Context()).
		Model(&validatorcore.ReportExchange{}).
		Where("test_run_id = ? AND endpoint_id = ?", runID, endpointID).
		Count(&n).Error; err != nil {
		t.Fatalf("count %s exchanges: %v", endpointID, err)
	}

	if int(n) != want {
		t.Fatalf("%s exchanges = %d, want %d", endpointID, n, want)
	}
}

func TestRedactBody_OmitsRawContent(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"token":"secret-value","authorization":"Bearer abc"}`)

	got := redactBody(raw)
	if got == "" {
		t.Fatal("redactBody must return a redaction marker")
	}

	if got == string(raw) || strings.Contains(got, "secret-value") || strings.Contains(got, "Bearer") {
		t.Fatalf("redacted %q still contains raw body", got)
	}
}

func assertEvidenceUsesLatestExchange(
	t *testing.T,
	store *validatorcore.Core,
	runID, area, endpointID string,
) {
	t.Helper()

	ev := mustLoadAreaEvidence(t, store, runID, area)
	if ev.ExchangeID == nil || *ev.ExchangeID == 0 {
		t.Fatalf("%s evidence missing exchange_id", area)
	}

	first := mustLoadOrderedExchange(t, store, runID, endpointID, true)
	latest := mustLoadOrderedExchange(t, store, runID, endpointID, false)

	if first.ExchangeID == latest.ExchangeID {
		t.Fatalf("%s last-wins must persist a new exchange, got only %d", endpointID, first.ExchangeID)
	}

	if *ev.ExchangeID != latest.ExchangeID {
		t.Fatalf("%s evidence exchange_id = %d, want latest %d", area, *ev.ExchangeID, latest.ExchangeID)
	}
}

func assertEvidenceUsesLatestRequest(
	t *testing.T,
	store *validatorcore.Core,
	runID, area, requestPrefix string,
) {
	t.Helper()

	ev := mustLoadAreaEvidence(t, store, runID, area)
	if ev.ExchangeID == nil || *ev.ExchangeID == 0 {
		t.Fatalf("%s evidence missing exchange_id", area)
	}

	first := mustLoadOrderedRequestPrefix(t, store, runID, requestPrefix, true)
	latest := mustLoadOrderedRequestPrefix(t, store, runID, requestPrefix, false)

	if first.ExchangeID == latest.ExchangeID {
		t.Fatalf("%s last-wins must persist a new exchange, got only %d", requestPrefix, first.ExchangeID)
	}

	if *ev.ExchangeID != latest.ExchangeID {
		t.Fatalf("%s evidence exchange_id = %d, want latest %d", area, *ev.ExchangeID, latest.ExchangeID)
	}
}

func mustLoadAreaEvidence(
	t *testing.T,
	store *validatorcore.Core,
	runID, area string,
) validatorcore.EvidenceRow {
	t.Helper()

	var ev validatorcore.EvidenceRow
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ?", runID, area).
		First(&ev).Error; err != nil {
		t.Fatalf("load %s evidence: %v", area, err)
	}

	return ev
}

func mustLoadOrderedExchange(
	t *testing.T,
	store *validatorcore.Core,
	runID, endpointID string,
	first bool,
) validatorcore.ReportExchange {
	t.Helper()

	order := "exchange_id DESC"
	if first {
		order = "exchange_id ASC"
	}

	var row validatorcore.ReportExchange
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND endpoint_id = ?", runID, endpointID).
		Order(order).
		First(&row).Error; err != nil {
		t.Fatalf("load %s exchange: %v", endpointID, err)
	}

	return row
}

func mustLoadOrderedRequestPrefix(
	t *testing.T,
	store *validatorcore.Core,
	runID, requestPrefix string,
	first bool,
) validatorcore.ReportExchange {
	t.Helper()

	order := "exchange_id DESC"
	if first {
		order = "exchange_id ASC"
	}

	var row validatorcore.ReportExchange
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND request_id LIKE ?", runID, requestPrefix+"%").
		Order(order).
		First(&row).Error; err != nil {
		t.Fatalf("load %s exchange: %v", requestPrefix, err)
	}

	return row
}

func assertStatsDiscoveryGrade(t *testing.T, store *validatorcore.Core, runID, want string) {
	t.Helper()

	var raw validatorcore.StatsRaw
	if err := store.DB().WithContext(t.Context()).
		Where("host_hash != ''").
		First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	_ = runID

	if raw.GradeDiscovery == nil || *raw.GradeDiscovery != want {
		t.Fatalf("stats grade_discovery = %v, want %q (evidence must precede fail)", raw.GradeDiscovery, want)
	}
}
