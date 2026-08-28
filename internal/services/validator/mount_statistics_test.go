// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func openMountTestStore(t *testing.T) *validatorcore.Core {
	t.Helper()

	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared",
		strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()),
	)

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}

	sqlDB.SetMaxOpenConns(1)

	if err := validatorcore.MigrateModels(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	return validatorcore.NewCore(db)
}

func TestMountPlaneARoutes_StatisticsAnonymousGET(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)

	r := chi.NewRouter()
	mountPlaneARoutes(r, passiveHandler, nil, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteAPIStatistics, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRouteSpecs_StatisticsPublicAnonymous(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var statsSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.ID == service.RouteIDValidatorAPIStatistics {
			statsSpec = &spec

			break
		}
	}

	if statsSpec == nil {
		t.Fatal("expected statistics route spec")
	}

	if statsSpec.SessionPolicy != service.SessionPublic {
		t.Fatalf("SessionPolicy = %q, want public", statsSpec.SessionPolicy)
	}

	if statsSpec.HandlerAuth != service.HandlerAuthNone {
		t.Fatalf("HandlerAuth = %q, want none", statsSpec.HandlerAuth)
	}

	if service.SessionAuthRequiredForPath("/validator/api/statistics", enabled) {
		t.Fatal("expected anonymous access to /validator/api/statistics")
	}
}

func TestValidatorService_MountsStatisticsRoute(t *testing.T) {
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

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/statistics", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
