// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAreaForEndpoint_HasNoTLSOrReverseInvite(t *testing.T) {
	t.Parallel()

	if _, ok := AreaForEndpoint("tls"); ok {
		t.Fatal("tls must not be a rater or exchange endpoint")
	}

	if _, ok := AreaForEndpoint("reverse_invite"); ok {
		t.Fatal("reverse_invite must not remain as an endpoint alias")
	}

	if area, ok := AreaForEndpoint(EndpointInviteAccepted); !ok || area != SpecificationAreaSharing {
		t.Fatalf("invite-accepted area = %q ok=%v, want sharing", area, ok)
	}

	if area, ok := AreaForEndpoint(EndpointOCMToken); !ok || area != SpecificationAreaToken {
		t.Fatalf("ocm-token area = %q ok=%v, want token", area, ok)
	}
}

func TestMapEvidenceScoreArea_AllowlistsAreasOnly(t *testing.T) {
	t.Parallel()

	if _, ok := mapEvidenceScoreArea("reverse_invite"); ok {
		t.Fatal("reverse_invite must not score")
	}

	if _, ok := mapEvidenceScoreArea("tls-endpoint"); ok {
		t.Fatal("unknown area must not score")
	}

	if got, ok := mapEvidenceScoreArea(SpecificationAreaTLS); !ok || got != SpecificationAreaTLS {
		t.Fatalf("tls area = %q ok=%v, want scored as evidence area", got, ok)
	}
}

func TestProjectPublicEvidence_OmitsExchangeIdentity(t *testing.T) {
	t.Parallel()

	grade := GradePass
	items := []SpecificationEvidence{{
		Source:          specificationEvidenceSourceRow,
		Leg:             evidenceLegForward,
		Area:            SpecificationAreaToken,
		Step:            evidenceStepTokenExchange,
		ReasonCode:      evidenceReasonTokenExchanged,
		Severity:        GradePass,
		Grade:           &grade,
		AffectsGrade:    true,
		PayloadRedacted: `{"grade":"pass"}`,
		CreatedAt:       10,
	}}

	out := ProjectPublicEvidence(items)
	if len(out) != 1 {
		t.Fatalf("projected = %d, want 1", len(out))
	}

	body := mustJSON(t, out)
	for _, banned := range []string{
		"exchangeId", "exchange_id", "inviteString", "authorization", "Bearer",
	} {
		if strings.Contains(body, banned) {
			t.Fatalf("public evidence leaked %q: %s", banned, body)
		}
	}

	var decoded []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(decoded) != 1 {
		t.Fatalf("decoded = %d, want 1", len(decoded))
	}

	allowed := map[string]bool{
		"source":          true,
		"leg":             true,
		"area":            true,
		"scoreArea":       true,
		"step":            true,
		"reasonCode":      true,
		"severity":        true,
		"grade":           true,
		"affectsGrade":    true,
		"payloadRedacted": true,
		"createdAt":       true,
	}

	for key := range decoded[0] {
		if !allowed[key] {
			t.Fatalf("public evidence key %q is not allowlisted", key)
		}
	}
}

func TestStaleRatingSymbolsRemoved(t *testing.T) {
	t.Parallel()

	src := validatorcoreProductionSource(t)
	for _, token := range []string{
		"ErrInvalidExchangeGrade",
		"overlay-wins",
		"overlayWins",
		"buildTerminalOverlay",
		"SetTerminalStatsSnapshot",
	} {
		if strings.Contains(src, token) {
			t.Fatalf("stale rating symbol %q must not remain", token)
		}
	}

	if strings.Contains(src, `EndpointTLS`) || strings.Contains(src, `endpointID = "tls"`) {
		t.Fatal("tls endpoint registration must not remain")
	}
}

func validatorcoreProductionSource(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	parts := make([]string, 0, len(entries))

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		body, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}

		parts = append(parts, string(body))
	}

	return strings.Join(parts, "\n")
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return string(raw)
}
