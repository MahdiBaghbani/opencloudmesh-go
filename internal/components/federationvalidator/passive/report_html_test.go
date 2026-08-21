// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleReportHTML_VisibilityStatusAndCache(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	now := time.Now().Unix()
	harvested := now
	router := newReportTestRouter(t, h)

	seedReportRun(t, store, &validatorcore.TestRun{TestRunID: "run-html-session"})
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      "run-html-permanent",
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
	})
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      "run-html-expired",
		State:          validatorcore.StateTerminalFail,
		OptInPermanent: true,
		HarvestedAt:    &harvested,
	})
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID: "run-html-not-saved",
		State:     validatorcore.StateInterrupted,
	})

	cases := []struct {
		name       string
		id         string
		wantStatus int
		wantCache  string
		cacheSet   bool
		wantBody   string
		forbid     []string
		plain404   bool
	}{
		{
			name:       "session",
			id:         "run-html-session",
			wantStatus: http.StatusOK,
			wantCache:  "no-store",
			cacheSet:   true,
			wantBody:   "run-html-session",
		},
		{
			name:       "permanent",
			id:         "run-html-permanent",
			wantStatus: http.StatusOK,
			wantCache:  "no-store",
			cacheSet:   true,
			wantBody:   "run-html-permanent",
		},
		{
			name:       "expired",
			id:         "run-html-expired",
			wantStatus: http.StatusGone,
			wantCache:  "public, max-age=3600",
			cacheSet:   true,
			wantBody:   "Report expired",
			forbid:     []string{"run-html-expired", "next-instruction"},
		},
		{
			name:       "not_saved",
			id:         "run-html-not-saved",
			wantStatus: http.StatusNotFound,
			wantBody:   "Report not saved",
			forbid:     []string{"run-html-not-saved", "next-instruction"},
		},
		{
			name:       "unknown",
			id:         "missing-run",
			wantStatus: http.StatusNotFound,
			wantBody:   "404 page not found",
			forbid:     []string{"Federation report", "Report not saved", "Report expired"},
			plain404:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+tc.id, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			gotCache := rec.Header().Get("Cache-Control")
			if tc.cacheSet && gotCache != tc.wantCache {
				t.Fatalf("Cache-Control = %q, want %q", gotCache, tc.wantCache)
			}

			body := rec.Body.String()
			if tc.wantBody != "" && !strings.Contains(body, tc.wantBody) {
				t.Fatalf("body %q does not contain %q", body, tc.wantBody)
			}

			for _, banned := range tc.forbid {
				if strings.Contains(body, banned) {
					t.Fatalf("body unexpectedly contains %q", banned)
				}
			}

			if tc.plain404 {
				contentType := rec.Header().Get("Content-Type")
				if !strings.HasPrefix(contentType, "text/plain") {
					t.Fatalf("Content-Type = %q, want text/plain", contentType)
				}
			}
		})
	}
}

func TestHandleReportHTML_RendersLockedFields(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	grade := "pass"
	runID := "run-html-fields"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		OptInStats:     true,
		OptInPermanent: true,
		OverallGrade:   &grade,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	want := []string{
		runID,
		validatorcore.StatePassiveRunning,
		validatorcore.SessionKindPassiveOnly,
		grade,
		"true",
		"/validator/report/" + runID,
		"/validator/api/session/" + runID,
		"/validator/api/report/" + runID,
		`id="next-instruction"`,
		"textContent",
	}
	for _, fragment := range want {
		if !strings.Contains(body, fragment) {
			t.Fatalf("report page missing %q", fragment)
		}
	}

	if strings.Contains(body, "innerHTML") {
		t.Fatal("report page must not use innerHTML")
	}
}

func TestHandleReportHTML_RendersSpecificationScore(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-html-score"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
	})
	seedReportEvidence(t, store, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	want := []string{
		`id="report-score-grade">pass<`,
		`id="report-score-coverage"`,
		"1 / 8",
		`id="report-score-areas"`,
		validatorcore.SpecificationAreaDiscovery,
		validatorcore.SpecificationAreaTLS,
		validatorcore.SpecificationAreaJWKS,
		validatorcore.SpecificationAreaHTTPSig,
		validatorcore.SpecificationAreaSharing,
		validatorcore.SpecificationAreaNotification,
		validatorcore.SpecificationAreaToken,
		validatorcore.SpecificationAreaCapability,
		`id="report-evidence-count"`,
		"textContent",
	}
	for _, fragment := range want {
		if !strings.Contains(body, fragment) {
			t.Fatalf("report page missing %q", fragment)
		}
	}

	for _, wrong := range []string{
		`id="report-score-grade">fail<`,
		`id="report-score-grade">warn<`,
		`id="report-score-grade">unassessed<`,
	} {
		if strings.Contains(body, wrong) {
			t.Fatalf("report page pinned wrong score grade %q", wrong)
		}
	}
}

func TestHandleReportHTML_SessionHidesEvidenceDetails(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-html-session-evidence"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		OptInPermanent: true,
	})
	seedReportEvidence(t, store, runID)
	seedLeakingExchange(t, store, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `id="report-evidence-count"`) {
		t.Fatal("session page must show evidence count")
	}

	if strings.Contains(body, `id="report-evidence"`) {
		t.Fatal("session page must hide evidence details")
	}

	if strings.Contains(body, reportLeakSecret) || strings.Contains(body, "redacted-capability-note") {
		t.Fatal("session page leaked evidence details")
	}
}

func TestHandleReportHTML_PermanentRendersRedactedEvidence(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-html-permanent-evidence"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
	})
	seedReportEvidence(t, store, runID)
	seedLeakingExchange(t, store, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `id="report-evidence"`) {
		t.Fatal("permanent page must render evidence list")
	}

	if !strings.Contains(body, "redacted-capability-note") || !strings.Contains(body, "webdav_get") {
		t.Fatal("permanent page must show redacted payload and evidence reason")
	}

	banned := []string{
		reportLeakSecret,
		"leak.example",
		"authorization",
		"password",
		"sig-" + reportLeakSecret,
	}
	for _, secret := range banned {
		if strings.Contains(body, secret) {
			t.Fatalf("permanent page leaked %q", secret)
		}
	}
}
