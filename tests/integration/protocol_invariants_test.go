// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"strings"
	"testing"

	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// allowedMembershipRefreshLogNeedles are log substrings that may appear when peer
// trust membership refresh runs against configured directory services. The strict
// protocol pair peer-trust variant ships with an empty directory_services list,
// so these needles are only relevant when a test wires a directory service.
var allowedMembershipRefreshLogNeedles = []string{
	"refreshing trust group membership",
	"failed to fetch directory service listing",
	"updated trust group membership",
}

// unexpectedProtocolOutboundNeedles indicate PROTOCOL-class outbound attempts
// that negative tests should not perform (share POST fallback, token exchange).
var unexpectedProtocolOutboundNeedles = []string{
	`"endpoint_path":"shares"`,
	`endpoint_path=shares`,
	"/ocm/shares",
	`"kind":"token-exchange"`,
	`kind=token-exchange`,
	"/ocm/token",
}

// allowedInboundShareRequestNeedles are access-log markers for rejected inbound
// POST /ocm/shares requests on the consumer under test.
var allowedInboundShareRequestNeedles = []string{
	`"method":"POST","path":"/ocm/shares"`,
}

// assertNoUnexpectedNetwork fails when subprocess logs show unexpected PROTOCOL
// outbound traffic. It allows peer-trust membership refresh log lines when a
// directory service is configured.
func assertNoUnexpectedNetwork(t *testing.T, servers []*harness.SubprocessServer, extraAllowed ...string) {
	t.Helper()

	allowed := append([]string{}, allowedMembershipRefreshLogNeedles...)
	allowed = append(allowed, extraAllowed...)

	for _, srv := range servers {
		if srv == nil {
			continue
		}
		logText := srv.ReadLog(t)
		for _, needle := range unexpectedProtocolOutboundNeedles {
			if !strings.Contains(logText, needle) {
				continue
			}
			if logLineAllowed(logText, needle, allowed) {
				continue
			}
			srv.DumpLogs(t)
			t.Fatalf("server %s log contains unexpected PROTOCOL outbound marker %q", srv.Name, needle)
		}
	}
}

// assertNoOutboundFallback fails when the strict recording receiver observed
// share POST traffic or subprocess logs suggest share-post fallback for stale trust.
func assertNoOutboundFallback(
	t *testing.T,
	receiver *strictRecordingReceiver,
	extraAllowed []string,
	servers ...*harness.SubprocessServer,
) {
	t.Helper()

	assertRecordingReceiverIdle(t, receiver)

	allowed := append([]string{}, allowedMembershipRefreshLogNeedles...)
	allowed = append(allowed, extraAllowed...)

	fallbackNeedles := []string{
		"outbound share",
		"POST /ocm/shares",
		"/ocm/shares",
	}
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		logText := srv.ReadLog(t)
		for _, needle := range fallbackNeedles {
			if strings.Contains(logText, needle) && !logLineAllowed(logText, needle, allowed) {
				srv.DumpLogs(t)
				t.Fatalf("server %s log suggests share-post fallback: found %q", srv.Name, needle)
			}
		}
	}
}

// assertPersistenceUnchanged fails when share or derived token persistence changed.
func assertPersistenceUnchanged(t *testing.T, before, after tsprotocol.PersistenceSnapshot) {
	t.Helper()

	if !tsprotocol.SnapshotEqual(before, after) {
		b, _ := tsprotocol.CanonicalSnapshotBytes(before)
		a, _ := tsprotocol.CanonicalSnapshotBytes(after)
		t.Fatalf("persistence changed\nbefore: %s\nafter: %s", string(b), string(a))
	}
}

// assertNoSecretInLogs fails when any provided secret appears in subprocess logs.
func assertNoSecretInLogs(t *testing.T, secrets []string, servers ...*harness.SubprocessServer) {
	t.Helper()

	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		for _, srv := range servers {
			if srv == nil {
				continue
			}
			if srv.LogContainsAny(secret) {
				srv.DumpLogs(t)
				t.Fatalf("server %s log contains secret substring", srv.Name)
			}
		}
	}
}

func logLineAllowed(logText, needle string, allowed []string) bool {
	for _, line := range strings.Split(logText, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		for _, permit := range allowed {
			if permit != "" && strings.Contains(line, permit) {
				return true
			}
		}
		return false
	}
	return false
}
