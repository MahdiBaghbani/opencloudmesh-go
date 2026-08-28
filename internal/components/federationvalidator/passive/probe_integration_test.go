// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/httpsigprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/platformdetect"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func tlsTestClient() *httpclient.Client {
	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true

	return httpclient.New(cfg, nil)
}

func discoveryTestPayload(serverURL string, extra map[string]any) map[string]any {
	endpoint := strings.TrimSuffix(serverURL, "/") + "/ocm"

	raw := map[string]any{
		"enabled":       true,
		"apiVersion":    "1.4.0",
		"endPoint":      endpoint,
		"resourceTypes": []any{},
		"criteria":      []any{},
	}

	maps.Copy(raw, extra)

	return raw
}

func TestProbeRunner_Integration_PersistsPlatformAndTLSGradeWithoutRawSecrets(t *testing.T) {
	t.Parallel()

	discoveryServer := newDiscoveryTLSServer(t)
	store := openHandlerTestStore(t)
	handler := newIntegrationHandler(t, store)
	ctx := context.Background()
	created := startContributeScan(t, handler, ctx, discoveryServer.URL)

	waitForState(t, store, ctx, created.ID)
	stopContributeScan(t, handler, ctx, created.ID)
	assertIntegrationStats(t, store, ctx, discoveryServer.URL)
	assertIntegrationRunMetadata(t, store, created.ID)
	assertPassiveFourAreaCeiling(t, store, created.ID)
	assertHTTPSigProbeSafety(t, store, created.ID)
	assertExchangeBodiesRedacted(t, store, created.ID)
}

func newDiscoveryTLSServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)

			return
		}

		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}

		raw := discoveryTestPayload(scheme+"://"+r.Host, map[string]any{
			"provider": "Nextcloud 28",
		})

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, raw)
	}))
	t.Cleanup(server.Close)

	return server
}

func newIntegrationHandler(t *testing.T, store *validatorcore.Core) *Handler {
	t.Helper()

	tlsClient := tlsTestClient()

	return NewHandlerWithDeps(ProbeDeps{
		Store:     store,
		Discovery: discovery.NewClient(tlsClient, cache.NewDefault()),
		HTTP:      httpclient.NewContextClient(tlsClient),
		Signer:    newIntegrationSigner(t),
	})
}

func startContributeScan(
	t *testing.T,
	handler *Handler,
	ctx context.Context,
	target string,
) startCreateResponse {
	t.Helper()

	// Seed through the store so loopback httptest targets can still exercise
	// the probe runner. The HTTP create path rejects non-public addresses.
	parsed, err := parseTarget(target)
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}

	testRunID, err := identity.UUIDv7()
	if err != nil {
		t.Fatalf("mint session id: %v", err)
	}

	now := time.Now().Unix()
	row := &validatorcore.TestRun{
		TestRunID:    testRunID,
		IsActive:     false,
		State:        validatorcore.StateCreated,
		TargetOrigin: parsed.origin,
		TargetHost:   parsed.targetHost,
		RemoteOCMID:  parsed.remoteOCMID,
		DiscoveryURL: strings.TrimSuffix(parsed.origin, "/") + "/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	applyCreateConsent(row, sessionOptIn{
		Stats:   true,
		Channel: validatorcore.OptInChannelScan,
	}, now)

	if err := handler.store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}

	handler.probe.StartAsync(context.WithoutCancel(ctx), testRunID)

	return startCreateResponse{
		ID:         testRunID,
		OptInStats: true,
	}
}

func stopContributeScan(t *testing.T, handler *Handler, ctx context.Context, runID string) {
	t.Helper()

	stopReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/stop", bytes.NewReader(mustJSON(t, map[string]string{"id": runID})))
	stopRec := httptest.NewRecorder()
	handler.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}
}

func assertIntegrationStats(t *testing.T, store *validatorcore.Core, ctx context.Context, targetURL string) {
	t.Helper()

	var raw validatorcore.StatsRaw
	if err := store.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.Platform != platformdetect.PlatformNextcloud {
		t.Fatalf("platform = %q, want %q", raw.Platform, platformdetect.PlatformNextcloud)
	}

	if raw.APIVersion != "1.4.0" {
		t.Fatalf("api_version = %q, want 1.4.0", raw.APIVersion)
	}

	if raw.GradeTLS == nil || *raw.GradeTLS != validatorcore.GradePass {
		t.Fatalf("grade_tls = %v, want pass", raw.GradeTLS)
	}

	if strings.Contains(raw.HostHash, "127.0.0.1") || strings.Contains(raw.HostHash, targetURL) {
		t.Fatalf("host_hash must not contain raw host or target URL, got %q", raw.HostHash)
	}

	if raw.Platform == "" {
		t.Fatal("expected platform in stats snapshot")
	}
}

func assertIntegrationRunMetadata(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	run := mustGetRun(t, store, runID)
	if run.Platform == nil || *run.Platform != platformdetect.PlatformNextcloud {
		t.Fatalf("test_run.platform = %v, want %q", run.Platform, platformdetect.PlatformNextcloud)
	}

	if run.APIVersion == nil || *run.APIVersion != "1.4.0" {
		t.Fatalf("test_run.api_version = %v, want 1.4.0", run.APIVersion)
	}
}

func newIntegrationSigner(t *testing.T) *crypto.RFC9421Signer {
	t.Helper()

	km := crypto.NewKeyManager("", "https://local.example")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	return crypto.NewRFC9421Signer(km)
}

func assertHTTPSigProbeSafety(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	var rows []validatorcore.ReportExchange
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND endpoint_id = ?", runID, httpsigprobe.EndpointID).
		Find(&rows).Error; err != nil {
		t.Fatalf("load httpsig exchanges: %v", err)
	}

	if len(rows) < 2 {
		t.Fatalf("httpsig-probe exchanges = %d, want at least 2", len(rows))
	}

	var haveValid, haveTampered bool

	for _, row := range rows {
		if row.EndpointID != httpsigprobe.EndpointID {
			t.Fatalf("endpoint_id = %q, want %q", row.EndpointID, httpsigprobe.EndpointID)
		}

		if strings.Contains(strings.ToLower(row.URL), "shares") {
			t.Fatalf("httpsig probe url %q must not target shares", row.URL)
		}

		if row.SigRaw == nil || *row.SigRaw == "" {
			t.Fatal("httpsig probe exchange must persist a signature")
		}

		id := requestIDOf(&row)
		switch {
		case strings.HasPrefix(id, requestIDHTTPSigTampered):
			haveTampered = true
		case strings.HasPrefix(id, requestIDHTTPSig):
			haveValid = true
		}
	}

	if !haveValid || !haveTampered {
		t.Fatal("httpsig differential must persist signed and tampered transcripts")
	}
}

func assertPassiveFourAreaCeiling(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	run := mustGetRun(t, store, runID)

	score, _, err := store.LoadSpecificationRating(t.Context(), run)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	if score.TotalAreas != 8 {
		t.Fatalf("total areas = %d, want 8", score.TotalAreas)
	}

	if score.AssessedAreas != 4 {
		t.Fatalf("assessed areas = %d, want 4 (passive ceiling)", score.AssessedAreas)
	}

	passive := map[string]bool{
		validatorcore.SpecificationAreaDiscovery: true,
		validatorcore.SpecificationAreaTLS:       true,
		validatorcore.SpecificationAreaJWKS:      true,
		validatorcore.SpecificationAreaHTTPSig:   true,
	}

	for _, area := range score.Areas {
		if passive[area.Area] {
			if area.Grade == nil {
				t.Fatalf("%s must be graded in a passive run", area.Area)
			}

			continue
		}

		if area.Grade != nil {
			t.Fatalf("%s must not be graded in passive-only, got %q", area.Area, *area.Grade)
		}
	}
}

func assertExchangeBodiesRedacted(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	var rows []validatorcore.ReportExchange
	if err := store.DB().WithContext(t.Context()).
		Where("test_run_id = ?", runID).
		Find(&rows).Error; err != nil {
		t.Fatalf("load exchanges: %v", err)
	}

	for _, row := range rows {
		assertRedactedField(t, row.ReqBodyRedacted, "req_body_redacted")
		assertRedactedField(t, row.RespBodyRedacted, "resp_body_redacted")
	}
}

func assertRedactedField(t *testing.T, value *string, field string) {
	t.Helper()

	if value == nil || *value == "" {
		return
	}

	rawLooking := strings.Contains(*value, "{") ||
		strings.Contains(*value, "enabled") ||
		strings.Contains(*value, "Nextcloud") ||
		strings.Contains(*value, "token")
	if rawLooking {
		t.Fatalf("%s still contains raw content: %q", field, *value)
	}
}

func TestProbeRunner_WithDiscoveryFailGates(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	discClient := discovery.NewClient(tlsTestClient(), cache.NewDefault())
	runner := NewProbeRunnerWithDiscovery(store, discClient, nil)
	ctx := context.Background()
	now := time.Now().Unix()
	runID := "run-async-probe-with-discovery"

	row := &validatorcore.TestRun{
		TestRunID:    runID,
		State:        validatorcore.StateCreated,
		TargetOrigin: "http://127.0.0.1:1",
		TargetHost:   "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	runner.run(ctx, runID)

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonPassiveProbeFailed {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonPassiveProbeFailed)
	}

	assertOneEvidenceArea(t, store, runID, validatorcore.SpecificationAreaDiscovery)
}
