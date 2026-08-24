// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	identityBindingWarnReason  = "accepter_user_unenforceable"
	identityBindingWarnMessage = "Identity binding could not be enforced for this session."
)

//go:embed templates/*.html
var reportTemplateFS embed.FS

var reportTemplates *template.Template

func init() {
	reportTemplates = template.Must(template.ParseFS(reportTemplateFS, "templates/*.html"))
}

type reportPageData struct {
	State                  string
	SessionKind            string
	Grade                  string
	OptInStats             bool
	OptInPermanent         bool
	Score                  validatorcore.SpecificationScore
	EvidenceCount          int
	Evidence               []validatorcore.SpecificationEvidence
	ShowEvidence           bool
	IdentityBindingWarning bool
	IdentityBindingMessage string
	NextInstructionLabel   string
	NextInstructionLabels  template.JS
	FailModeLabel          string
}

// HandleReportHTML serves GET /report/{id}.
func (h *Handler) HandleReportHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		http.Error(w, "validator store is not configured", http.StatusInternalServerError)

		return
	}

	row, vis, err := h.classifyRequestedReport(r)
	if err != nil {
		http.Error(w, "validator store error", http.StatusInternalServerError)

		return
	}

	switch vis {
	case ReportVisibilitySession, ReportVisibilityPermanent:
		data, buildErr := h.buildReportPageData(r.Context(), row, vis)
		if buildErr != nil {
			http.Error(w, "validator store error", http.StatusInternalServerError)

			return
		}

		setReportCacheControl(w, vis)
		h.writeReportTemplate(w, "report.html", http.StatusOK, data)
	case ReportVisibilityExpired:
		setReportCacheControl(w, vis)
		h.writeReportTemplate(w, "expired.html", http.StatusGone, reportPageData{})
	case ReportVisibilityNotSaved:
		h.writeReportTemplate(w, "not_saved.html", http.StatusNotFound, reportPageData{})
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) buildReportPageData(
	ctx context.Context,
	row *validatorcore.TestRun,
	visibility string,
) (reportPageData, error) {
	if row == nil {
		return reportPageData{}, nil
	}

	data := reportPageData{
		State:                 row.State,
		SessionKind:           validatorcore.SessionKindOf(row),
		OptInStats:            row.OptInStats,
		OptInPermanent:        row.OptInPermanent,
		ShowEvidence:          visibility == ReportVisibilityPermanent,
		NextInstructionLabel:  validatorcore.NextInstructionLabel(validatorcore.NextInstructionForRun(row)),
		NextInstructionLabels: nextInstructionLabelsJS(),
		FailModeLabel:         validatorcore.TerminalReasonLabel(row.State, terminalReasonOf(row)),
	}
	if row.OverallGrade != nil {
		data.Grade = *row.OverallGrade
	}

	score, evidence, err := h.store.LoadSpecificationRating(ctx, row)
	if err != nil {
		return reportPageData{}, fmt.Errorf("load specification rating: %w", err)
	}

	data.Score = score
	data.EvidenceCount = len(evidence)

	data.IdentityBindingWarning = hasIdentityBindingWarning(evidence)
	if data.IdentityBindingWarning {
		data.IdentityBindingMessage = identityBindingWarnMessage
	}

	if data.ShowEvidence {
		data.Evidence = evidence
	}

	return data, nil
}

func nextInstructionLabelsJS() template.JS {
	raw, err := json.Marshal(catalog.InstructionLabels()) //nolint:errchkjson // static string map
	if err != nil {
		return template.JS("{}")
	}

	return template.JS(raw) //nolint:gosec // labels are static catalog strings
}

func hasIdentityBindingWarning(evidence []validatorcore.SpecificationEvidence) bool {
	for _, row := range evidence {
		if row.ReasonCode == identityBindingWarnReason && row.Severity == validatorcore.GradeWarn {
			return true
		}
	}

	return false
}

func (h *Handler) writeHTMLTemplate(
	w http.ResponseWriter,
	name string,
	status int,
	data any,
) {
	var buf bytes.Buffer
	if err := reportTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	if _, err := w.Write(buf.Bytes()); err != nil {
		logutil.NoopIfNil(h.log).Warn("failed to write HTML page", "error", err)
	}
}

func (h *Handler) writeReportTemplate(
	w http.ResponseWriter,
	name string,
	status int,
	data reportPageData,
) {
	h.writeHTMLTemplate(w, name, status, data)
}
