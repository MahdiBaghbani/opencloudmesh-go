// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"net/http"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// runOutboundDiscoveryFailureCase drives one outbound negative case whose peer
// discovery fails (cross-authority, redirect-ssrf, malformed document). The
// label identifies the scenario in failure messages.
func runOutboundDiscoveryFailureCase(
	t *testing.T,
	pair *harness.StrictProtocolPair,
	receiver *trustedProtocolPeer,
	recordingReceiver *strictRecordingReceiver,
	label string,
) {
	t.Helper()

	provider := pair.Server1

	if receiver.DiscoveryHits() > 0 {
		t.Fatalf("%s peer discovery hit before outgoing share attempt", label)
	}

	token := loginSubprocessAdminWithClient(t, provider)
	shareFile := writeNegativeShareFile(t, provider.TempDir, label)

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before %s: %v", label, err)
	}

	status, body := createOutgoingShareWithClient(t, provider, token, map[string]any{
		"receiverDomain": receiver.peerBaseURL,
		"shareWith":      "bob@" + receiver.peerDomain,
		"localPath":      shareFile,
		"permissions":    []string{"read"},
	})

	wantStatus := reason.APIStatus(reason.PeerDiscoveryFailed)
	if status != wantStatus {
		provider.DumpLogs(t)
		t.Fatalf("%s outgoing share: expected %d, got %d: %s", label, wantStatus, status, body)
	}

	if receiver.DiscoveryHits() == 0 {
		t.Fatalf("expected discovery fetch before %s rejection", label)
	}

	if receiver.PostCount() > 0 {
		t.Fatalf("expected no outbound /ocm/shares, receiver postCount=%d", receiver.PostCount())
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after %s: %v", label, err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{provider})
	assertNoOutboundFallback(t, recordingReceiver, nil, provider)
	assertNoSecretInLogs(t, nil, provider)
}

func runOutboundStaleTrustMembershipCase(
	t *testing.T,
	pair *harness.StrictProtocolPair,
	recordingReceiver *strictRecordingReceiver,
) {
	t.Helper()

	provider := pair.Server1
	consumer := pair.Server2
	consumerHost := hostFromBaseURL(t, consumer.BaseURL)

	token := loginSubprocessAdminWithClient(t, provider)
	shareFile := writeNegativeShareFile(t, provider.TempDir, "stale-trust-membership")

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before stale-trust membership: %v", err)
	}

	status, body := createOutgoingShareWithClient(t, provider, token, map[string]any{
		"receiverDomain": consumerHost,
		"shareWith":      "admin@" + consumerHost,
		"localPath":      shareFile,
		"permissions":    []string{"read"},
	})

	wantStatus := http.StatusBadGateway
	if status != wantStatus {
		provider.DumpLogs(t)
		consumer.DumpLogs(t)
		t.Fatalf("stale-trust outgoing share: expected %d, got %d: %s", wantStatus, status, body)
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after stale-trust membership: %v", err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{provider})
	assertNoOutboundFallback(t, recordingReceiver, nil, provider)
	assertNoSecretInLogs(t, nil, provider, consumer)
}

func writeNegativeShareFile(t *testing.T, serverTempDir, label string) string {
	t.Helper()

	return writeShareFileInContentRoot(
		t,
		serverTempDir,
		"negative-share-"+label+".txt",
		[]byte("negative integration share payload for "+label),
	)
}

func startCrossAuthorityDiscoveryPeer(t *testing.T) *trustedProtocolPeer {
	t.Helper()

	return startTrustedProtocolPeer(t, func(peer *trustedProtocolPeer, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "https://other-authority.example.com/ocm",
				TokenEndPoint: peer.peerBaseURL + "/ocm/token",
				Capabilities:  []string{"exchange-token", "http-sig"},
				Criteria:      []string{spec.CriteriaMustExchangeToken, spec.CriteriaMustUseHTTPSig},
				ResourceTypes: []spec.ResourceType{{Name: "file", ShareTypes: []string{"user"}, Protocols: spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")}}},
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)
		case "/ocm/shares":
			if r.Method == http.MethodPost {
				peer.postCount.Add(1)
			}

			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func startRedirectSSRFDiscoveryPeer(t *testing.T) *trustedProtocolPeer {
	t.Helper()

	return startTrustedProtocolPeer(t, func(peer *trustedProtocolPeer, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			http.Redirect(w, r, "http://127.0.0.1:1/.well-known/ocm", http.StatusFound)
		case "/ocm/shares":
			if r.Method == http.MethodPost {
				peer.postCount.Add(1)
			}

			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
