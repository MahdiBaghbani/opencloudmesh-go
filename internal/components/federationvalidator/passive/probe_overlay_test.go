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

func TestBuildTerminalOverlay_PopulatesConnectionReport(t *testing.T) {
	t.Parallel()

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

	store := openHandlerTestStore(t)
	runner := NewProbeRunnerWithDiscovery(store, discovery.NewClient(tlsTestClient(), cache.NewDefault()), nil)
	ctx := context.Background()
	now := time.Now().Unix()
	runID := "run-overlay-report"

	row := &validatorcore.TestRun{
		TestRunID:    runID,
		State:        validatorcore.StatePassiveRunning,
		SessionKind:  validatorcore.SessionKindPassiveOnly,
		TargetOrigin: server.URL,
		TargetHost:   strings.TrimPrefix(strings.TrimPrefix(server.URL, "https://"), "http://"),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	overlay, ok := runner.buildTerminalOverlay(ctx, runID)
	if !ok {
		t.Fatal("expected overlay")
	}

	if overlay.Platform != platformdetect.PlatformNextcloud {
		t.Fatalf("platform = %q, want %q", overlay.Platform, platformdetect.PlatformNextcloud)
	}

	if overlay.ConnectionReport == nil {
		t.Fatal("expected connection report on snapshot overlay")
	}

	if overlay.ConnectionReport.ServerIP == "" {
		t.Fatal("expected connected server IP in report detail")
	}

	if overlay.ConnectionReport.TLSVersion == "" {
		t.Fatal("expected TLS version in report detail")
	}

	if overlay.ConnectionReport.CipherSuite == "" {
		t.Fatal("expected cipher suite in report detail")
	}

	if overlay.GradeTLS == nil || *overlay.GradeTLS != validatorcore.GradePass {
		t.Fatalf("grade_tls = %v, want pass", overlay.GradeTLS)
	}

	raw := overlay.ToStatsRaw()
	if raw.GradeTLS == nil || *raw.GradeTLS != validatorcore.GradePass {
		t.Fatalf("persisted grade_tls = %v, want pass", raw.GradeTLS)
	}
}
