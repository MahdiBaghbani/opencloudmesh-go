// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"encoding/json"
	"strings"
	"testing"
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

func TestStatsSnapshotFromTestRun_DoesNotCarryConnectionReport(t *testing.T) {
	t.Parallel()

	platform := "nextcloud"
	row := &TestRun{Platform: &platform}

	snap := statsSnapshotFromTestRun(row, "hash-a", 200)
	if snap.ConnectionReport != nil {
		t.Fatalf("connection report = %#v, want nil", snap.ConnectionReport)
	}

	raw := snap.ToStatsRaw()
	if raw.Platform != "nextcloud" {
		t.Fatalf("platform = %q", raw.Platform)
	}
}
