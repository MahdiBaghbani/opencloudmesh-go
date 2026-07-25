// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func runOutboundCrossAuthorityCase(
	t *testing.T,
	pair *harness.StrictProtocolPair,
	receiver *trustedProtocolPeer,
	recordingReceiver *strictRecordingReceiver,
) {
	t.Helper()

	provider := pair.Server1
	if receiver.DiscoveryHits() > 0 {
		t.Fatal("cross-authority peer discovery hit before outgoing share attempt")
	}

	token := loginSubprocessAdminWithClient(t, provider)
	shareFile := writeNegativeShareFile(t, "cross-authority")

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before cross-authority: %v", err)
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
		t.Fatalf("cross-authority outgoing share: expected %d, got %d: %s", wantStatus, status, body)
	}
	if receiver.DiscoveryHits() == 0 {
		t.Fatal("expected discovery fetch before cross-authority rejection")
	}
	if receiver.PostCount() > 0 {
		t.Fatalf("expected no outbound /ocm/shares, receiver postCount=%d", receiver.PostCount())
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after cross-authority: %v", err)
	}
	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{provider})
	assertNoOutboundFallback(t, recordingReceiver, nil, provider)
	assertNoSecretInLogs(t, nil, provider)
}

func runOutboundRedirectSSRFCase(
	t *testing.T,
	pair *harness.StrictProtocolPair,
	receiver *trustedProtocolPeer,
	recordingReceiver *strictRecordingReceiver,
) {
	t.Helper()

	provider := pair.Server1
	if receiver.DiscoveryHits() > 0 {
		t.Fatal("redirect-ssrf peer discovery hit before outgoing share attempt")
	}

	token := loginSubprocessAdminWithClient(t, provider)
	shareFile := writeNegativeShareFile(t, "redirect-ssrf")

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before redirect-ssrf: %v", err)
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
		t.Fatalf("redirect-ssrf outgoing share: expected %d, got %d: %s", wantStatus, status, body)
	}
	if receiver.DiscoveryHits() == 0 {
		t.Fatal("expected discovery fetch before redirect-ssrf rejection")
	}
	if receiver.PostCount() > 0 {
		t.Fatalf("expected no outbound /ocm/shares, receiver postCount=%d", receiver.PostCount())
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after redirect-ssrf: %v", err)
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
	shareFile := writeNegativeShareFile(t, "stale-trust-membership")

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

func writeNegativeShareFile(t *testing.T, label string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "negative-share-"+label+".txt")
	if err := os.WriteFile(path, []byte("negative integration share payload for "+label), 0644); err != nil {
		t.Fatalf("write share file: %v", err)
	}
	return path
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
			_ = json.NewEncoder(w).Encode(disc)
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
