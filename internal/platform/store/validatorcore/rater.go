// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"fmt"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec/wire"
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

const (
	specificationEvidenceSourceRow      = "evidenceRow"
	specificationEvidenceSourceExchange = "reportExchange"

	endpointDiscovery      = "discovery"
	endpointJWKS           = "jwks"
	endpointHTTPSigProbe   = "httpsig-probe"
	endpointShares         = "shares"
	endpointInviteAccepted = "invite-accepted"
	endpointNotifications  = wire.CapabilityNotifications
	endpointOCMToken       = "ocm-token"
	endpointWebDAV         = wire.ProtocolWebDAV
)

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

// SpecificationEvidence is one redacted evidence or exchange summary.
type SpecificationEvidence struct {
	Source          string  `json:"source"`
	Area            string  `json:"area,omitempty"`
	ScoreArea       string  `json:"scoreArea,omitempty"`
	Step            string  `json:"step,omitempty"`
	ReasonCode      string  `json:"reasonCode,omitempty"`
	ReasonCodes     *string `json:"reasonCodes,omitempty"`
	Severity        string  `json:"severity,omitempty"`
	Grade           *string `json:"grade"`
	AffectsGrade    bool    `json:"affectsGrade"`
	PayloadRedacted string  `json:"payloadRedacted,omitempty"`
	ExchangeID      *uint   `json:"exchangeId,omitempty"`
	Sequence        int     `json:"sequence,omitempty"`
	EndpointID      string  `json:"endpointId,omitempty"`
	Direction       string  `json:"direction,omitempty"`
	Method          string  `json:"method,omitempty"`
	StatusCode      *int    `json:"statusCode,omitempty"`
	SignatureValid  *bool   `json:"signatureValid,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
}

// RateSpecification folds evidence rows and report exchanges into a
// deterministic specification score. TestRun.OverallGrade is not read.
func RateSpecification(
	run *TestRun,
	evidenceRows []EvidenceRow,
	exchanges []ReportExchange,
) (SpecificationScore, []SpecificationEvidence, error) {
	if run == nil {
		return SpecificationScore{}, nil, ErrNilTestRun
	}

	areas := newAreaFoldSet()
	evidence := make([]SpecificationEvidence, 0, len(evidenceRows)+len(exchanges))

	foldEvidenceRows(areas, evidenceRows, &evidence)

	if err := foldReportExchanges(areas, exchanges, &evidence); err != nil {
		return SpecificationScore{}, nil, err
	}

	areaScores := areas.scores()
	assessed := countAssessedAreas(areaScores)

	return SpecificationScore{
		Grade:         overallSpecificationGrade(run.State, areaScores),
		State:         run.State,
		Terminal:      isTerminalState(run.State),
		AssessedAreas: assessed,
		TotalAreas:    len(specificationAreaOrder),
		Areas:         areaScores,
	}, evidence, nil
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

func foldSpecificationAreas(
	evidenceRows []EvidenceRow,
	exchanges []ReportExchange,
) ([]SpecificationAreaScore, error) {
	areas := newAreaFoldSet()

	foldEvidenceRows(areas, evidenceRows, nil)

	if err := foldReportExchanges(areas, exchanges, nil); err != nil {
		return nil, err
	}

	return areas.scores(), nil
}

func foldEvidenceRows(
	areas *areaFoldSet,
	rows []EvidenceRow,
	dest *[]SpecificationEvidence,
) {
	for _, row := range rows {
		item := specificationEvidenceFromRow(row)
		appendSpecificationEvidence(dest, item)

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

func foldReportExchanges(
	areas *areaFoldSet,
	exchanges []ReportExchange,
	dest *[]SpecificationEvidence,
) error {
	for _, ex := range exchanges {
		item := specificationEvidenceFromExchange(ex)
		appendSpecificationEvidence(dest, item)

		if ex.Grade == nil {
			if scoreArea, ok := mapEndpointScoreArea(ex.EndpointID); ok {
				areas.byName[scoreArea].evidenceCount++
			}

			continue
		}

		if !isExactGrade(*ex.Grade) {
			return fmt.Errorf("%w: %q", ErrInvalidExchangeGrade, *ex.Grade)
		}

		scoreArea, ok := mapEndpointScoreArea(ex.EndpointID)
		if !ok {
			continue
		}

		fold := areas.byName[scoreArea]
		fold.evidenceCount++
		fold.applyGrade(*ex.Grade)
		fold.gradedEvidenceCount++
	}

	return nil
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
		Area:         row.Area,
		Step:         row.Step,
		ReasonCode:   row.ReasonCode,
		Severity:     row.Severity,
		AffectsGrade: row.AffectsGrade,
		ExchangeID:   row.ExchangeID,
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

func specificationEvidenceFromExchange(ex ReportExchange) SpecificationEvidence {
	item := SpecificationEvidence{
		Source:         specificationEvidenceSourceExchange,
		ReasonCodes:    ex.ReasonCodes,
		Grade:          cloneString(ex.Grade),
		AffectsGrade:   ex.Grade != nil,
		Sequence:       ex.Seq,
		EndpointID:     ex.EndpointID,
		Direction:      ex.Direction,
		Method:         ex.Method,
		StatusCode:     ex.StatusCode,
		SignatureValid: ex.SigValid,
		CreatedAt:      ex.CreatedAt,
	}

	if ex.ExchangeID != 0 {
		id := ex.ExchangeID
		item.ExchangeID = &id
	}

	if mapped, ok := mapEndpointScoreArea(ex.EndpointID); ok {
		item.ScoreArea = mapped
	}

	return item
}

func appendSpecificationEvidence(dest *[]SpecificationEvidence, item SpecificationEvidence) {
	if dest == nil {
		return
	}

	*dest = append(*dest, item)
}

func mapEvidenceScoreArea(area string) (string, bool) {
	switch area {
	case SpecificationAreaDiscovery,
		SpecificationAreaTLS,
		SpecificationAreaJWKS,
		SpecificationAreaHTTPSig,
		SpecificationAreaSharing,
		SpecificationAreaNotification,
		SpecificationAreaToken,
		SpecificationAreaCapability:
		return area, true
	case evidenceAreaReverseInvite:
		return SpecificationAreaSharing, true
	default:
		return "", false
	}
}

func mapEndpointScoreArea(endpointID string) (string, bool) {
	switch endpointID {
	case endpointDiscovery:
		return SpecificationAreaDiscovery, true
	case endpointJWKS:
		return SpecificationAreaJWKS, true
	case endpointHTTPSigProbe:
		return SpecificationAreaHTTPSig, true
	case endpointShares, endpointInviteAccepted:
		return SpecificationAreaSharing, true
	case endpointNotifications:
		return SpecificationAreaNotification, true
	case endpointOCMToken:
		return SpecificationAreaToken, true
	case endpointWebDAV:
		return SpecificationAreaCapability, true
	default:
		return "", false
	}
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

func isExactGrade(grade string) bool {
	switch grade {
	case GradePass, GradeWarn, GradeFail:
		return true
	default:
		return false
	}
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

func hasReverseInviteAcceptance(rows []EvidenceRow) bool {
	for _, row := range rows {
		if row.Area == evidenceAreaReverseInvite {
			return true
		}
	}

	return false
}
