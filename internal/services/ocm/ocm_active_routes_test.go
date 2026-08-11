// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func activeOCMPostRouteRows(t *testing.T) []service.RouteRow {
	t.Helper()

	cfg := config.DevConfig()
	rows := service.DerivedRouteInventory(service.RouteOptsFromConfig(cfg))

	out := make([]service.RouteRow, 0, len(rows))
	for _, row := range rows {
		if row.Service == "ocm" && row.Method == http.MethodPost {
			out = append(out, row)
		}
	}

	return out
}

func expectedOCMPostPaths(t *testing.T) []string {
	t.Helper()

	tokenPath := ""

	for _, row := range activeOCMPostRouteRows(t) {
		if row.ID == service.RouteIDOCMToken {
			tokenPath = row.FullPath

			break
		}
	}

	if tokenPath == "" {
		t.Fatal("configured token route is missing")
	}

	paths := []string{
		"/ocm" + RouteShares,
		"/ocm" + RouteInviteAccepted,
		"/ocm" + RouteNotifications,
		tokenPath,
	}
	slices.Sort(paths)

	return paths
}

func TestActiveOCMRoutes(t *testing.T) {
	t.Parallel()
	rows := activeOCMPostRouteRows(t)

	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.FullPath)
	}

	slices.Sort(got)

	want := expectedOCMPostPaths(t)
	if !slices.Equal(got, want) {
		t.Fatalf("active OCM POST routes = %v, want %v", got, want)
	}
}

func TestOCMPostRoutes_RequireSignatures(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, mountedPath := range expectedOCMPostPaths(t) {
		t.Run(mountedPath, func(t *testing.T) {
			t.Parallel()

			contentType := "application/json"
			body := []byte(`{"shareWith":"user@remote.example","name":"test","providerId":"provider-123","owner":"owner@local.example","sender":"sender@remote.example","shareType":"user","resourceType":"file","protocol":{"name":"webdav"}}`)

			switch mountedPath {
			case "/ocm" + RouteInviteAccepted:
				body = []byte(`{"recipientProvider":"remote.example","token":"invite-token","userID":"user-1","email":"user@remote.example","name":"Remote User"}`)
			case "/ocm" + RouteShares:
			default:
				contentType = "application/x-www-form-urlencoded"
				body = []byte("grant_type=authorization_code&client_id=remote.example&code=secret-code")
			}

			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost,
				strings.TrimPrefix(mountedPath, "/ocm"),
				bytes.NewReader(body),
			)
			req.Header.Set("Content-Type", contentType)

			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unsigned POST %s returned %d: %s", mountedPath, w.Code, w.Body.String())
			}
		})
	}
}

func TestOCMRequestBodyLimit(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := []byte(`{"sender":"sender@remote.example","padding":"` + strings.Repeat("x", 1<<20) + `"}`)
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost,
		strings.TrimPrefix("/ocm"+RouteShares, "/ocm"),
		bytes.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Fatalf("body over 1 MiB returned %d: signature verification happened before required body-limit rejection", w.Code)
	}

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over 1 MiB returned %d: %s", w.Code, w.Body.String())
	}
}

func TestService_RoutingSmoke(t *testing.T) {
	t.Parallel()

	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"shares", "/shares"},
		{"invite-accepted", "/invite-accepted"},
		{"notifications", "/notifications"},
		{"token", "/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("GET %s: expected status 405, got %d", tt.path, w.Code)
			}
		})
	}
}
