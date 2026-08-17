// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/platformdetect"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
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

	discoveryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(discoveryServer.Close)

	store := openHandlerTestStore(t)
	discClient := discovery.NewClient(tlsTestClient(), cache.NewDefault())
	h := NewHandlerWithDiscovery(store, discClient, nil)
	ctx := context.Background()

	createReq := httptest.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"/api/scan?target="+discoveryServer.URL+"&contribute=1",
		nil,
	)
	createRec := httptest.NewRecorder()
	h.HandleScan(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("scan status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	waitForState(t, store, ctx, created.ID, validatorcore.StatePassiveComplete)

	stopBody := mustJSON(t, map[string]string{"id": created.ID})
	stopReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}

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

	if strings.Contains(raw.HostHash, "127.0.0.1") || strings.Contains(raw.HostHash, discoveryServer.URL) {
		t.Fatalf("host_hash must not contain raw host or target URL, got %q", raw.HostHash)
	}

	if raw.Platform == "" {
		t.Fatal("expected platform in stats snapshot")
	}
}

func TestProbeRunner_WithDiscoveryStillReachesPassiveComplete(t *testing.T) {
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
		SessionKind:  validatorcore.SessionKindPassiveOnly,
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

	if got.State != validatorcore.StatePassiveComplete {
		t.Fatalf("state = %q, want %q", got.State, validatorcore.StatePassiveComplete)
	}
}
