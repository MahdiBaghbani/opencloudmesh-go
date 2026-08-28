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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
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
