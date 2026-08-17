// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustJSONBytes(t *testing.T, value any) []byte {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return data
}

func TestStatsSnapshot_ToStatsRaw_ExcludesConnectionReport(t *testing.T) {
	t.Parallel()

	pass := GradePass
	report := &StatsConnectionReport{
		ServerIP:    "203.0.113.10",
		TLSVersion:  "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		LeafCN:      "peer.example",
		LeafSANs:    []string{"peer.example"},
		ReasonCodes: []string{"plain_http"},
	}

	snap := StatsSnapshot{
		HostHash:         "abc",
		SessionKind:      SessionKindPassiveOnly,
		Platform:         "nextcloud",
		APIVersion:       "1.4.0",
		GradeTLS:         &pass,
		ConnectionReport: report,
		CreatedAt:        42,
	}

	if snap.ConnectionReport == nil || snap.ConnectionReport.ServerIP != "203.0.113.10" {
		t.Fatal("expected snapshot to retain connection report detail")
	}

	raw := snap.ToStatsRaw()
	if raw.Platform != "nextcloud" {
		t.Fatalf("platform = %q, want nextcloud", raw.Platform)
	}

	if raw.GradeTLS == nil || *raw.GradeTLS != GradePass {
		t.Fatalf("grade_tls = %v, want pass", raw.GradeTLS)
	}

	payload := string(mustJSONBytes(t, raw))
	for _, forbidden := range []string{
		"203.0.113.10",
		"TLS 1.3",
		"TLS_AES_128_GCM_SHA256",
		"peer.example",
		"plain_http",
		"connection_report",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("stats_raw must not contain report-only detail %q", forbidden)
		}
	}
}

func TestMergeTerminalStatsOverlay_CopiesConnectionReport(t *testing.T) {
	t.Parallel()

	base := StatsSnapshot{
		HostHash:    "hash-a",
		SessionKind: SessionKindPassiveOnly,
		CreatedAt:   100,
	}
	overlay := StatsSnapshot{
		Platform: "nextcloud",
		ConnectionReport: &StatsConnectionReport{
			ServerIP:      "203.0.113.10",
			TLSVersion:    "TLS 1.3",
			CipherSuite:   "TLS_AES_128_GCM_SHA256",
			CertNotBefore: time.Unix(100, 0).UTC(),
			CertNotAfter:  time.Unix(200, 0).UTC(),
			CertValid:     true,
			LeafCN:        "peer.example",
			LeafSANs:      []string{"peer.example", "alt.example"},
			ReasonCodes:   []string{"ok"},
		},
	}

	mergeTerminalStatsOverlay(&base, &overlay)

	if base.ConnectionReport == nil {
		t.Fatal("expected copied connection report")
	}

	if base.ConnectionReport.ServerIP != "203.0.113.10" {
		t.Fatalf("server IP = %q", base.ConnectionReport.ServerIP)
	}

	if len(base.ConnectionReport.LeafSANs) != 2 {
		t.Fatalf("leaf SAN count = %d, want 2", len(base.ConnectionReport.LeafSANs))
	}

	base.ConnectionReport.LeafSANs[0] = "mutated"
	if overlay.ConnectionReport.LeafSANs[0] == "mutated" {
		t.Fatal("expected deep copy of leaf SANs")
	}
}

func TestStatsSnapshotFromTestRun_RetainsConnectionReport(t *testing.T) {
	t.Parallel()

	row := &TestRun{SessionKind: SessionKindPassiveOnly}
	overlay := &StatsSnapshot{
		Platform: "nextcloud",
		ConnectionReport: &StatsConnectionReport{
			ServerIP:   "203.0.113.10",
			TLSVersion: "TLS 1.3",
		},
	}

	snap := statsSnapshotFromTestRun(row, "hash-a", 200, overlay)
	if snap.ConnectionReport == nil || snap.ConnectionReport.TLSVersion != "TLS 1.3" {
		t.Fatalf("connection report = %#v, want TLS 1.3 detail", snap.ConnectionReport)
	}

	raw := snap.ToStatsRaw()
	if raw.Platform != "nextcloud" {
		t.Fatalf("platform = %q", raw.Platform)
	}
}
