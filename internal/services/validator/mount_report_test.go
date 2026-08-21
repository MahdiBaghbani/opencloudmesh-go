// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestMountValidatorRoutes_ReportAnonymousGET(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)
	runID := "run-mount-report"
	now := int64(1_700_000_100)
	row := &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateCreated,
		TargetHost:     "peer.example",
		OptInPermanent: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := chi.NewRouter()
	mountValidatorRoutes(r, passiveHandler, nil, nil, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("json status = %d, want 200", rec.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["schema"] != "federation_tester_report.v1" {
		t.Fatalf("schema = %v", payload["schema"])
	}

	htmlReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	htmlRec := httptest.NewRecorder()
	r.ServeHTTP(htmlRec, htmlReq)

	if htmlRec.Code != http.StatusOK {
		t.Fatalf("html status = %d, want 200", htmlRec.Code)
	}
}

func TestValidatorService_MountsReportRoute(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	runID := "run-svc-report"
	now := int64(1_700_000_200)
	row := &validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StateCreated,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc, err := New(Inputs{
		Store: store,
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// stubPoster is a canned InviteAcceptedPoster for mount-level tests; the
// paste route never reaches the wire on these requests.
type stubPoster struct{}

func (stubPoster) PostInviteAccepted(_ context.Context, _ string, _ []byte) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"userID":"sender@peer.example"}`)),
	}, nil
}

func newReverseInviteService(t *testing.T, store *validatorcore.Core) *reverseinvite.Service {
	t.Helper()

	r, err := repos.New(t.Context(), config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repos.New: %v", err)
	}

	t.Cleanup(func() { tshttp.MustClose(t, r) })

	svc, err := reverseinvite.New(reverseinvite.Deps{
		Store:           store,
		OutgoingInvites: r.OutgoingInvites,
		IncomingInvites: r.IncomingInvites,
		Parties:         identity.NewMemoryPartyRepo(),
		Poster:          stubPoster{},
		LocalIdentity: localidentity.Identity{
			Origin:                "https://local.example",
			Scheme:                "https",
			ProviderDomain:        "local.example",
			ProviderDomainCompare: "local.example",
		},
	})
	if err != nil {
		t.Fatalf("reverseinvite.New: %v", err)
	}

	return svc
}

func TestValidatorService_ReverseInviteMountedAndAdvertised(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)

	svc, err := New(Inputs{
		Store:         store,
		ReverseInvite: newReverseInviteService(t, store),
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The paste route is mounted: a malformed body reaches the handler and
	// fails as a 400, not a chi 404.
	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/api/session/run-1/reverse-invite",
		strings.NewReader("not json"),
	)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatal("reverse-invite route not mounted")
	}

	// And the aggregate advertises it once mounted.
	opts := service.DefaultRouteOpts()
	opts.ValidatorEnabled = true

	found := false

	for _, row := range service.Routes(opts) {
		if row.ID == service.RouteIDValidatorAPISessionReverseInvite {
			found = true

			if !row.MatchExact {
				t.Error("reverse-invite row MatchExact = false, want true")
			}
		}
	}

	if !found {
		t.Fatal("reverse-invite route not advertised after mount")
	}
}

func TestValidatorService_ReverseInviteAbsentWithoutService(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)

	svc, err := New(Inputs{
		Store: store,
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(
		t.Context(), http.MethodPost, "/api/session/run-1/reverse-invite",
		strings.NewReader(`{"inviteString":"x"}`),
	)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when the reverse-invite service is not wired", rec.Code)
	}
}
