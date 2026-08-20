// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const reportSchema = "federation_tester_report.v1"

const (
	codeReportExpired     = "report_expired"
	codeReportNotPublic   = "report_not_public"
	codeReportNotTerminal = "report_not_terminal"
	codeRetentionLocked   = "retention_locked"
	codeInvalidTier       = "invalid_retention_tier"
)

// reportJSONResponse is the federation_tester_report.v1 success payload.
// Additive fields only; keys are camelCase per .golangci.yml json: camel.
type reportJSONResponse struct {
	Schema        string  `json:"schema"`
	ID            string  `json:"id"`
	Visibility    string  `json:"visibility"`
	ReportURL     string  `json:"reportUrl"`
	URL           string  `json:"url,omitempty"`
	RetentionTier *string `json:"retentionTier"`
}

type reportExpiredJSONResponse struct {
	Schema     string `json:"schema"`
	ID         string `json:"id"`
	Visibility string `json:"visibility"`
}

// HandleReportJSON serves GET /api/report/{id}.
func (h *Handler) HandleReportJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	row, vis, err := h.classifyRequestedReport(r)
	if err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	switch vis {
	case ReportVisibilitySession, ReportVisibilityPermanent:
		setReportCacheControl(w, vis)
		writeJSON(w, h.log, http.StatusOK, h.buildReportJSON(r, row, vis))
	case ReportVisibilityExpired:
		setReportCacheControl(w, vis)
		writeJSON(w, h.log, http.StatusGone, buildExpiredReportJSON(r, row))
	case ReportVisibilityNotSaved:
		writeJSONError(w, h.log, http.StatusNotFound, codeReportNotPublic, "report is not public")
	default:
		writeJSONError(
			w,
			h.log,
			http.StatusNotFound,
			validatorcore.CodeSessionNotFound,
			"session not found",
		)
	}
}

func (h *Handler) classifyRequestedReport(
	r *http.Request,
) (*validatorcore.TestRun, string, error) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		return nil, ReportVisibilityUnknown, nil
	}

	row, err := h.store.GetTestRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			return nil, ReportVisibilityUnknown, nil
		}

		return nil, "", fmt.Errorf("load report: %w", err)
	}

	return row, ClassifyReport(row, time.Now().Unix()), nil
}

func (h *Handler) buildReportJSON(
	r *http.Request,
	row *validatorcore.TestRun,
	visibility string,
) reportJSONResponse {
	id := strings.TrimSpace(chi.URLParam(r, "id"))

	var tier *string

	if row != nil {
		id = row.TestRunID
		tier = row.RetentionTier
	}

	pathHint := joinReportPath(h.externalBasePath, "validator", "report", id)
	payload := reportJSONResponse{
		Schema:        reportSchema,
		ID:            id,
		Visibility:    visibility,
		ReportURL:     pathHint,
		RetentionTier: tier,
	}

	if abs := requestAbsoluteURL(r, pathHint); abs != "" {
		payload.URL = abs
	}

	return payload
}

func buildExpiredReportJSON(r *http.Request, row *validatorcore.TestRun) reportExpiredJSONResponse {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if row != nil {
		id = row.TestRunID
	}

	return reportExpiredJSONResponse{
		Schema:     reportSchema,
		ID:         id,
		Visibility: ReportVisibilityExpired,
	}
}

func setReportCacheControl(w http.ResponseWriter, visibility string) {
	switch visibility {
	case ReportVisibilitySession, ReportVisibilityPermanent:
		w.Header().Set("Cache-Control", "no-store")
	case ReportVisibilityExpired:
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
}

func requestAbsoluteURL(r *http.Request, pathHint string) string {
	if r == nil || r.URL == nil {
		return ""
	}

	scheme := strings.ToLower(strings.TrimSpace(r.URL.Scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = strings.TrimSpace(r.URL.Host)
	}

	if host == "" {
		return ""
	}

	return scheme + "://" + host + pathHint
}
