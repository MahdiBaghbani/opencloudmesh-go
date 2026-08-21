// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const reportLeakSecret = "s3cret-token-value"

func seedReportEvidence(
	t *testing.T,
	store *validatorcore.Core,
	runID string,
) {
	t.Helper()

	payload := "redacted-capability-note"

	row := &validatorcore.EvidenceRow{
		TestRunID:       runID,
		Area:            validatorcore.SpecificationAreaCapability,
		Step:            "file_opened",
		ReasonCode:      "webdav_get",
		Severity:        validatorcore.GradePass,
		AffectsGrade:    true,
		PayloadRedacted: &payload,
		CreatedAt:       time.Now().Unix(),
	}
	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
}

func seedLeakingExchange(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	pass := validatorcore.GradePass
	status := 200
	sigValid := true
	reasons := "httpsig_ok"
	secret := reportLeakSecret
	host := "leak.example"
	reqHdr := `{"authorization":"Bearer ` + secret + `"}`
	respHdr := `{"x-secret":"` + secret + `"}`
	reqBody := `{"password":"` + secret + `"}`
	respBody := `{"token":"` + secret + `"}`
	sigRaw := "sig-" + secret

	row := &validatorcore.ReportExchange{
		TestRunID:        runID,
		Seq:              1,
		CapturedAt:       1,
		Direction:        "out",
		EndpointID:       "webdav",
		Method:           "GET",
		URL:              "https://leak.example/ocm?token=" + secret,
		Host:             &host,
		StatusCode:       &status,
		ReqHeadersJSON:   &reqHdr,
		RespHeadersJSON:  &respHdr,
		SigRaw:           &sigRaw,
		SigValid:         &sigValid,
		ReqBodyRedacted:  &reqBody,
		RespBodyRedacted: &respBody,
		ReqBodyRaw:       []byte(reqBody),
		RespBodyRaw:      []byte(respBody),
		Grade:            &pass,
		ReasonCodes:      &reasons,
		CreatedAt:        1,
	}
	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed exchange: %v", err)
	}
}

func TestHandleReportJSON_SessionAddsScoreWithoutEvidence(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-session-score"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		OptInPermanent: true,
	})
	seedReportEvidence(t, store, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := payload["evidence"]; ok {
		t.Fatal("session report must omit evidence")
	}

	var score validatorcore.SpecificationScore
	if err := json.Unmarshal(payload["score"], &score); err != nil {
		t.Fatalf("score: %v", err)
	}

	if score.State != validatorcore.StatePassiveRunning {
		t.Fatalf("score.state = %q", score.State)
	}

	if score.Grade != nil {
		t.Fatalf("session overall grade = %q, want nil", *score.Grade)
	}

	if score.AssessedAreas != 1 || score.TotalAreas != 8 {
		t.Fatalf("coverage = %d/%d", score.AssessedAreas, score.TotalAreas)
	}
}

func TestHandleReportJSON_PermanentAddsScoreAndEvidence(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-permanent-score"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
	})
	seedReportEvidence(t, store, runID)
	seedLeakingExchange(t, store, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}

	raw := rec.Body.String()
	if !strings.Contains(raw, "redacted-capability-note") || !strings.Contains(raw, "httpsig_ok") {
		t.Fatal("permanent report must include redacted reason and payload")
	}

	if strings.Contains(raw, reportLeakSecret) || strings.Contains(raw, "leak.example") {
		t.Fatal("permanent report leaked raw host, url, or secret")
	}

	if strings.Contains(raw, "authorization") || strings.Contains(raw, "password") {
		t.Fatal("permanent report leaked raw headers or bodies")
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := payload["evidence"]; !ok {
		t.Fatal("permanent report must include evidence")
	}

	var evidence []validatorcore.SpecificationEvidence
	if err := json.Unmarshal(payload["evidence"], &evidence); err != nil {
		t.Fatalf("evidence: %v", err)
	}

	if len(evidence) != 2 {
		t.Fatalf("evidence = %d, want 2", len(evidence))
	}

	var score validatorcore.SpecificationScore
	if err := json.Unmarshal(payload["score"], &score); err != nil {
		t.Fatalf("score: %v", err)
	}

	if score.Grade == nil || *score.Grade != validatorcore.GradePass {
		t.Fatalf("score.grade = %v, want pass", score.Grade)
	}
}
