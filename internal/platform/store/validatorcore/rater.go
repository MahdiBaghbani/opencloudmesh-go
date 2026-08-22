// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"slices"
	"strings"
)

// Canonical specification areas. Order matches statsAreaOrder.
const (
	SpecificationAreaDiscovery    = "discovery"
	SpecificationAreaTLS          = "tls"
	SpecificationAreaJWKS         = "jwks"
	SpecificationAreaHTTPSig      = "httpsig"
	SpecificationAreaSharing      = "sharing"
	SpecificationAreaNotification = "notification"
	SpecificationAreaToken        = "token"
	SpecificationAreaCapability   = "capability"
)

const specificationEvidenceSourceRow = "evidenceRow"

// specificationAreaOrder is the stable public area list. It stays aligned
// with statsAreaOrder by sharing these names.
var specificationAreaOrder = []string{
	SpecificationAreaDiscovery,
	SpecificationAreaTLS,
	SpecificationAreaJWKS,
	SpecificationAreaHTTPSig,
	SpecificationAreaSharing,
	SpecificationAreaNotification,
	SpecificationAreaToken,
	SpecificationAreaCapability,
}

// SpecificationScore is the folded specification rating for one test run.
type SpecificationScore struct {
	Grade         *string                  `json:"grade"`
	State         string                   `json:"state"`
	Terminal      bool                     `json:"terminal"`
	AssessedAreas int                      `json:"assessedAreas"`
	TotalAreas    int                      `json:"totalAreas"`
	Areas         []SpecificationAreaScore `json:"areas"`
}

// SpecificationAreaScore is one canonical area's folded grade and counts.
type SpecificationAreaScore struct {
	Area                string  `json:"area"`
	Grade               *string `json:"grade"`
	EvidenceCount       int     `json:"evidenceCount"`
	GradedEvidenceCount int     `json:"gradedEvidenceCount"`
}

// SpecificationEvidence is one redacted evidence_row observation.
type SpecificationEvidence struct {
	Source          string  `json:"source"`
	Leg             string  `json:"leg,omitempty"`
	Area            string  `json:"area,omitempty"`
	ScoreArea       string  `json:"scoreArea,omitempty"`
	Step            string  `json:"step,omitempty"`
	ReasonCode      string  `json:"reasonCode,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	Grade           *string `json:"grade"`
	AffectsGrade    bool    `json:"affectsGrade"`
	PayloadRedacted string  `json:"payloadRedacted,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
}

// RateSpecification folds evidence rows into a deterministic specification
// score. Report exchanges are accepted for call compatibility and are not
// scored or emitted. TestRun.OverallGrade is not read.
func RateSpecification(
	run *TestRun,
	evidenceRows []EvidenceRow,
	_ []ReportExchange,
) (SpecificationScore, []SpecificationEvidence, error) {
	if run == nil {
		return SpecificationScore{}, nil, ErrNilTestRun
	}

	areas := newAreaFoldSet()
	evidence := make([]SpecificationEvidence, 0, len(evidenceRows))

	foldEvidenceRows(areas, evidenceRows, &evidence)

	areaScores := areas.scores()
	assessed := countAssessedAreas(areaScores)

	return SpecificationScore{
		Grade:         overallSpecificationGrade(run.State, areaScores),
		State:         run.State,
		Terminal:      isTerminalState(run.State),
		AssessedAreas: assessed,
		TotalAreas:    len(specificationAreaOrder),
		Areas:         areaScores,
	}, ProjectPublicEvidence(evidence), nil
}

type areaFold struct {
	area                string
	grade               *string
	evidenceCount       int
	gradedEvidenceCount int
}

type areaFoldSet struct {
	order  []*areaFold
	byName map[string]*areaFold
}

func newAreaFoldSet() *areaFoldSet {
	set := &areaFoldSet{
		order:  make([]*areaFold, 0, len(specificationAreaOrder)),
		byName: make(map[string]*areaFold, len(specificationAreaOrder)),
	}

	for _, name := range specificationAreaOrder {
		fold := &areaFold{area: name}
		set.order = append(set.order, fold)
		set.byName[name] = fold
	}

	return set
}

func (s *areaFoldSet) scores() []SpecificationAreaScore {
	out := make([]SpecificationAreaScore, 0, len(s.order))

	for _, fold := range s.order {
		out = append(out, SpecificationAreaScore{
			Area:                fold.area,
			Grade:               cloneString(fold.grade),
			EvidenceCount:       fold.evidenceCount,
			GradedEvidenceCount: fold.gradedEvidenceCount,
		})
	}

	return out
}

func foldSpecificationAreas(evidenceRows []EvidenceRow) []SpecificationAreaScore {
	areas := newAreaFoldSet()
	foldEvidenceRows(areas, evidenceRows, nil)

	return areas.scores()
}

func foldEvidenceRows(
	areas *areaFoldSet,
	rows []EvidenceRow,
	dest *[]SpecificationEvidence,
) {
	for _, row := range rows {
		item := specificationEvidenceFromRow(row)
		appendSpecificationEvidence(dest, item)

		// Reverse-share facts score only from the reverse leg so a
		// passive or forward row cannot set reverse-share stats.
		if isReverseInviteAcceptanceTuple(row) && item.Leg != evidenceLegReverse {
			continue
		}

		scoreArea, ok := mapEvidenceScoreArea(row.Area)
		if !ok {
			continue
		}

		fold := areas.byName[scoreArea]
		fold.evidenceCount++

		if !row.AffectsGrade {
			continue
		}

		fold.applyGrade(severityToGrade(row.Severity))
		fold.gradedEvidenceCount++
	}
}

func (f *areaFold) applyGrade(grade string) {
	if f.grade == nil {
		f.grade = cloneString(&grade)

		return
	}

	worse := worseGrade(*f.grade, grade)
	f.grade = &worse
}

func specificationEvidenceFromRow(row EvidenceRow) SpecificationEvidence {
	item := SpecificationEvidence{
		Source:       specificationEvidenceSourceRow,
		Leg:          evidenceRowLeg(row),
		Area:         row.Area,
		Step:         row.Step,
		ReasonCode:   row.ReasonCode,
		Severity:     row.Severity,
		AffectsGrade: row.AffectsGrade,
		CreatedAt:    row.CreatedAt,
	}

	if mapped, ok := mapEvidenceScoreArea(row.Area); ok && mapped != row.Area {
		item.ScoreArea = mapped
	}

	if row.PayloadRedacted != nil {
		item.PayloadRedacted = *row.PayloadRedacted
	}

	if row.AffectsGrade {
		grade := severityToGrade(row.Severity)
		item.Grade = &grade
	}

	return item
}

func appendSpecificationEvidence(dest *[]SpecificationEvidence, item SpecificationEvidence) {
	if dest == nil {
		return
	}

	*dest = append(*dest, item)
}

func severityToGrade(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case GradeFail, "failure", "critical", "error", "fatal":
		return GradeFail
	case GradeWarn, "warning", "important":
		return GradeWarn
	default:
		return GradePass
	}
}

func worseGrade(a, b string) string {
	if a == GradeFail || b == GradeFail {
		return GradeFail
	}

	if a == GradeWarn || b == GradeWarn {
		return GradeWarn
	}

	return GradePass
}

func overallSpecificationGrade(state string, areas []SpecificationAreaScore) *string {
	switch state {
	case StateTerminalFail:
		grade := GradeFail

		return &grade
	case StateTerminalPass:
		if hasAreaGrade(areas, GradeFail) {
			grade := GradeFail

			return &grade
		}

		if hasAreaGrade(areas, GradeWarn) {
			grade := GradeWarn

			return &grade
		}

		if countAssessedAreas(areas) >= 1 {
			grade := GradePass

			return &grade
		}

		return nil
	default:
		return nil
	}
}

func hasAreaGrade(areas []SpecificationAreaScore, want string) bool {
	for _, area := range areas {
		if area.Grade != nil && *area.Grade == want {
			return true
		}
	}

	return false
}

func countAssessedAreas(areas []SpecificationAreaScore) int {
	var n int

	for _, area := range areas {
		if area.Grade != nil {
			n++
		}
	}

	return n
}

func cloneString(src *string) *string {
	if src == nil {
		return nil
	}

	copied := *src

	return &copied
}

func evidenceRowLeg(row EvidenceRow) string {
	if row.Leg == nil {
		return ""
	}

	return *row.Leg
}

func isReverseInviteAcceptanceTuple(row EvidenceRow) bool {
	return row.Area == SpecificationAreaSharing &&
		row.Step == evidenceStepInviteAccepted &&
		row.ReasonCode == evidenceReasonReverseAccepted
}

func isReverseInviteAcceptance(row EvidenceRow) bool {
	return isReverseInviteAcceptanceTuple(row) && evidenceRowLeg(row) == evidenceLegReverse
}

func hasReverseInviteAcceptance(rows []EvidenceRow) bool {
	return slices.ContainsFunc(rows, isReverseInviteAcceptance)
}
