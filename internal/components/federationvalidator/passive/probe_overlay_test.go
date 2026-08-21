// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/platformdetect"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCollectPassiveProbeFacts_PersistsPlatformAndTLSGrade(t *testing.T) {
	t.Parallel()

	server := newNextcloudDiscoveryTLSServer(t)
	store := openHandlerTestStore(t)
	runner := NewProbeRunnerWithDiscovery(store, discovery.NewClient(tlsTestClient(), cache.NewDefault()), nil)
	ctx := context.Background()
	now := time.Now().Unix()
	runID := "run-probe-facts"

	row := &validatorcore.TestRun{
		TestRunID:    runID,
		State:        validatorcore.StatePassiveRunning,
		TargetOrigin: server.URL,
		TargetHost:   strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://"),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	facts, ok := runner.collectPassiveProbeFacts(ctx, runID)
	if !ok {
		t.Fatal("expected probe facts")
	}

	assertCollectedProbeFacts(t, facts)

	if err := store.RecordPassiveProbeFacts(ctx, runID, facts.platform, facts.apiVersion, facts.tlsGrade); err != nil {
		t.Fatalf("record facts: %v", err)
	}

	assertPersistedPlatformAndTLS(t, store, ctx, runID)
}

func newNextcloudDiscoveryTLSServer(t *testing.T) *httptest.Server {
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

func assertCollectedProbeFacts(t *testing.T, facts passiveProbeFacts) {
	t.Helper()

	if facts.platform != platformdetect.PlatformNextcloud {
		t.Fatalf("platform = %q, want %q", facts.platform, platformdetect.PlatformNextcloud)
	}

	if facts.tlsGrade == nil || *facts.tlsGrade != validatorcore.GradePass {
		t.Fatalf("grade_tls = %v, want pass", facts.tlsGrade)
	}
}

func assertPersistedPlatformAndTLS(
	t *testing.T,
	store *validatorcore.Core,
	ctx context.Context,
	runID string,
) {
	t.Helper()

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.Platform == nil || *got.Platform != platformdetect.PlatformNextcloud {
		t.Fatalf("persisted platform = %v, want %q", got.Platform, platformdetect.PlatformNextcloud)
	}

	var evidence []validatorcore.EvidenceRow

	if err := store.DB().WithContext(ctx).
		Where("test_run_id = ? AND area = ?", runID, validatorcore.SpecificationAreaTLS).
		Find(&evidence).Error; err != nil {
		t.Fatalf("load tls evidence: %v", err)
	}

	if len(evidence) != 1 {
		t.Fatalf("tls evidence rows = %d, want 1", len(evidence))
	}

	if evidence[0].ReasonCode != "tls_probed" || evidence[0].Severity != validatorcore.GradePass {
		t.Fatalf("tls evidence = %+v, want tls_probed/pass", evidence[0])
	}
}
