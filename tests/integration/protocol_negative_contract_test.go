// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func runMalformedDiscoveryBlocksOutboundCase( //nolint:dupl // intentional: parallel negative outbound helpers share harness flow but assert different failure scenarios

	t *testing.T,
	pair *harness.StrictProtocolPair,
	receiver *trustedProtocolPeer,
	recordingReceiver *strictRecordingReceiver,
) {
	t.Helper()

	provider := pair.Server1

	if receiver.DiscoveryHits() > 0 {
		t.Fatal("malformed-discovery peer hit before outgoing share attempt")
	}

	token := loginSubprocessAdminWithClient(t, provider)
	shareFile := writeNegativeShareFile(t, "malformed-discovery")

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before malformed discovery: %v", err)
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
		t.Fatalf("malformed discovery outgoing share: expected %d, got %d: %s", wantStatus, status, body)
	}

	if receiver.DiscoveryHits() == 0 {
		t.Fatal("expected trusted discovery fetch before malformed-discovery rejection")
	}

	if receiver.PostCount() > 0 {
		t.Fatalf("expected receiver POST count 0, got %d", receiver.PostCount())
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after malformed discovery: %v", err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{provider})
	assertNoOutboundFallback(t, recordingReceiver, nil, provider)
	assertNoSecretInLogs(t, nil, provider)
}

func runUnexchangedSharedSecretBearer401Case(
	t *testing.T,
	pair *harness.StrictProtocolPair,
	recordingReceiver *strictRecordingReceiver,
) {
	t.Helper()

	provider := pair.Server1
	consumer := pair.Server2

	testContent := []byte("strict negative shared-secret bearer proof")

	testFile := filepath.Join(t.TempDir(), "protocol-negative-bearer.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	providerToken := loginSubprocessAdminWithClient(t, provider)
	consumerToken := loginSubprocessAdminWithClient(t, consumer)
	consumerHost := hostFromBaseURL(t, consumer.BaseURL)

	// Strict mode enforces must-invite: exchange an invite before the share.
	exchangeInvitesBetweenPair(t, provider, consumer, providerToken, consumerToken)

	status, body := createOutgoingShareWithClient(t, provider, providerToken, map[string]any{
		"receiverDomain": consumerHost,
		"shareWith":      "admin@" + consumerHost,
		"localPath":      testFile,
		"permissions":    []string{"read"},
	})
	if status != http.StatusCreated {
		provider.DumpLogs(t)
		consumer.DumpLogs(t)
		t.Fatalf("outgoing multi share setup: expected 201, got %d: %s", status, body)
	}

	var outgoingCreated struct {
		ProviderID string `json:"providerId"`
		WebDAVID   string `json:"webdavId"`
	}
	if err := json.Unmarshal([]byte(body), &outgoingCreated); err != nil {
		t.Fatalf("decode outgoing share response: %v", err)
	}

	sharedSecret := readOutgoingSharedSecret(t, provider, outgoingCreated.ProviderID)
	if sharedSecret == "" {
		t.Fatal("outgoing persistence missing shared secret for bearer rejection proof")
	}

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before shared-secret bearer: %v", err)
	}

	fileName := filepath.Base(testFile)
	webdavURL := provider.BaseURL + "/webdav/ocm/" + outgoingCreated.WebDAVID + "/" + url.PathEscape(fileName)

	req, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("create shared-secret bearer webdav request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+sharedSecret)

	resp, err := provider.Client().Do(req)
	if err != nil {
		t.Fatalf("shared-secret bearer webdav GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		respBody, err := io.ReadAll(resp.Body) //nolint:govet // shadow: sequential err in table-driven test is benign
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("shared-secret bearer webdav: expected 401, got %d: %s", resp.StatusCode, respBody)
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after shared-secret bearer: %v", err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{provider})
	assertNoOutboundFallback(t, recordingReceiver, nil, provider)
	assertNoSecretInLogs(t, []string{sharedSecret}, provider, consumer)
}

func startMalformedDiscoveryPeer(t *testing.T) *trustedProtocolPeer {
	t.Helper()

	return startTrustedProtocolPeer(t, func(peer *trustedProtocolPeer, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     peer.peerBaseURL + "/ocm",
				Capabilities: []string{"exchange-token"},
				Criteria:     []string{},
				ResourceTypes: []spec.ResourceType{{
					Name:       "file",
					ShareTypes: []string{"user"},
					Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")},
				}},
			}

			w.Header().Set("Content-Type", "application/json")
			//nolint:errcheck // test stub handler: JSON encode/decode
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
