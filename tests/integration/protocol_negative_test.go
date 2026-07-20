// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// Unit-primary negative tiers are not re-proved here in subprocess integration:
//   - non-Bearer credential: internal/components/webdav/webdav_test.go TestServeHTTP_BasicAuthRejected401
//   - expired exchanged token: internal/components/webdav/webdav_test.go TestServeHTTP_BearerWithExpiredTokenFails401
//   - oversized body: internal/services/ocm/ocm_test.go TestOCMRequestBodyLimit
//   - stale trust membership refresh: internal/components/ocm/peertrust/membership_test.go

// TestProtocolNegativeStrict is the Step 14 negative proof: strict subprocess
// rejection classes with persistence, network, fallback, and log invariants.
func TestProtocolNegativeStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	t.Run("inbound", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantProtocolPair,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)
		runInboundNegativeCases(t, pair, recordingReceiver)
	})

	t.Run("outbound_cross_authority_endpoint", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		receiver := startCrossAuthorityDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}
		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantProtocolPair, extraPorts)
		defer pair.Stop(t)
		runOutboundCrossAuthorityCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("outbound_redirect_ssrf", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		receiver := startRedirectSSRFDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}
		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantSSRFStrictRedirect, extraPorts)
		defer pair.Stop(t)
		runOutboundRedirectSSRFCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("outbound_stale_trust_membership", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantPeerTrustStaleMembership,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)
		runOutboundStaleTrustMembershipCase(t, pair, recordingReceiver)
	})

	t.Run("contract_malformed_discovery_blocks_outbound_post", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		receiver := startMalformedDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}
		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantProtocolPair, extraPorts)
		defer pair.Stop(t)
		runMalformedDiscoveryBlocksOutboundCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("contract_unexchanged_shared_secret_bearer_401", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()
		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantProtocolPair,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)
		runUnexchangedSharedSecretBearer401Case(t, pair, recordingReceiver)
	})
}

type inboundNegativeCase struct {
	name       string
	wantStatus int
	act        func(t *testing.T, env inboundNegativeEnv) (secrets []string)
}

type inboundNegativeEnv struct {
	provider     *harness.SubprocessServer
	consumer     *harness.SubprocessServer
	providerHost string
	consumerHost string
	signer       *crypto.RFC9421Signer
}

func runInboundNegativeCases(t *testing.T, pair *harness.StrictProtocolPair, recordingReceiver *strictRecordingReceiver) {
	t.Helper()

	provider := pair.Server1
	consumer := pair.Server2
	providerHost := hostFromBaseURL(t, provider.BaseURL)
	consumerHost := hostFromBaseURL(t, consumer.BaseURL)
	signer := subprocessSigner(t, provider)

	env := inboundNegativeEnv{
		provider:     provider,
		consumer:     consumer,
		providerHost: providerHost,
		consumerHost: consumerHost,
		signer:       signer,
	}

	cases := []inboundNegativeCase{
		{
			name:       "unsigned_request",
			wantStatus: http.StatusUnauthorized,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-unsigned-secret"
				body := buildSignedInboundShareBody(
					"admin@"+env.consumerHost,
					"step14-neg-unsigned",
					env.providerHost,
					"webdav",
					"webdav-uri-unsigned",
					secret,
				)
				resp := postJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusUnauthorized)
				return []string{secret}
			},
		},
		{
			name:       "wrong_signature_authority",
			wantStatus: http.StatusForbidden,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-wrong-authority-secret"
				wrongHost := "wrong-authority.invalid"
				body := buildSignedInboundShareBody(
					"admin@"+env.consumerHost,
					"step14-neg-wrong-authority",
					wrongHost,
					"webdav",
					"webdav-uri-wrong-authority",
					secret,
				)
				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusForbidden)
				return []string{secret}
			},
		},
		{
			name:       "owner_provider_mismatch",
			wantStatus: http.StatusForbidden,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-owner-mismatch-secret"
				body := buildInboundShareBodyWithOwnerSender(
					"admin@"+env.consumerHost,
					"step14-neg-owner-mismatch",
					"foreign-owner.invalid",
					env.providerHost,
					"webdav",
					"webdav-uri-owner-mismatch",
					secret,
				)
				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusForbidden)
				return []string{secret}
			},
		},
		{
			name:       "foreign_labels_without_ocm_signature",
			wantStatus: http.StatusUnauthorized,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-foreign-labels-secret"
				body := buildInboundShareBodyWithOwnerSender(
					"admin@"+env.consumerHost,
					"step14-neg-foreign-labels",
					env.providerHost,
					env.providerHost,
					"webdav",
					"webdav-uri-foreign-labels",
					secret,
				)
				req, err := http.NewRequest(http.MethodPost, env.consumer.BaseURL+"/ocm/shares", bytes.NewReader(body))
				if err != nil {
					t.Fatalf("build POST with foreign labels only: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				setForeignSignatureLabelsOnly(req)
				resp, err := env.consumer.Client().Do(req)
				if err != nil {
					t.Fatalf("POST with foreign labels only: %v", err)
				}
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusUnauthorized)
				return []string{secret}
			},
		},
		{
			name:       "duplicate_ocm_signature",
			wantStatus: http.StatusUnauthorized,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-duplicate-ocm-secret"
				body := buildSignedInboundShareBody(
					"admin@"+env.consumerHost,
					"step14-neg-duplicate-ocm",
					env.providerHost,
					"webdav",
					"webdav-uri-duplicate-ocm",
					secret,
				)
				req, err := http.NewRequest(http.MethodPost, env.consumer.BaseURL+"/ocm/shares", bytes.NewReader(body))
				if err != nil {
					t.Fatalf("build signed POST: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				if err := env.signer.SignRequest(req, body); err != nil {
					t.Fatalf("sign POST: %v", err)
				}
				duplicateOCMSignatureLabel(req)
				resp, err := env.consumer.Client().Do(req)
				if err != nil {
					t.Fatalf("signed POST with duplicate ocm label: %v", err)
				}
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusUnauthorized)
				return []string{secret}
			},
		},
		{
			name:       "invalid_protocol_structure",
			wantStatus: http.StatusBadRequest,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-invalid-structure-secret"
				body := []byte(fmt.Sprintf(`{
					"shareWith": %q,
					"name": "step14-neg-invalid-structure.txt",
					"providerId": "step14-neg-invalid-structure",
					"owner": %q,
					"sender": %q,
					"shareType": "user",
					"resourceType": "file",
					"protocol": {
						"webdav": {
							"uri": "webdav-uri-invalid-structure",
							"sharedSecret": %q,
							"permissions": ["read"],
							"requirements": ["must-exchange-token"]
						}
					}
				}`, "admin@"+env.consumerHost,
					address.FormatOutgoingOCMAddressFromUserID("step14-owner", env.providerHost),
					address.FormatOutgoingOCMAddressFromUserID("step14-sender", env.providerHost),
					secret))
				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusBadRequest)
				return []string{secret}
			},
		},
		{
			name:       "unsupported_protocol_arm",
			wantStatus: http.StatusNotImplemented,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-unsupported-arm-secret"
				body := []byte(fmt.Sprintf(`{
					"shareWith": %q,
					"name": "step14-neg-unsupported-arm.txt",
					"providerId": "step14-neg-unsupported-arm",
					"owner": %q,
					"sender": %q,
					"shareType": "user",
					"resourceType": "file",
					"protocol": {
						"name": "webdav",
						"webdav": {
							"uri": "webdav-uri-unsupported-arm",
							"sharedSecret": %q,
							"permissions": ["read"],
							"requirements": ["must-exchange-token"]
						},
						"datatx": {}
					}
				}`, "admin@"+env.consumerHost,
					address.FormatOutgoingOCMAddressFromUserID("step14-owner", env.providerHost),
					address.FormatOutgoingOCMAddressFromUserID("step14-sender", env.providerHost),
					secret))
				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusNotImplemented)
				return []string{secret}
			},
		},
		{
			name:       "unknown_requirement",
			wantStatus: http.StatusNotImplemented,
			act: func(t *testing.T, env inboundNegativeEnv) []string {
				secret := "step14-neg-unknown-req-secret"
				body := []byte(fmt.Sprintf(`{
					"shareWith": %q,
					"name": "step14-neg-unknown-req.txt",
					"providerId": "step14-neg-unknown-req",
					"owner": %q,
					"sender": %q,
					"shareType": "user",
					"resourceType": "file",
					"protocol": {
						"name": "webdav",
						"webdav": {
							"uri": "webdav-uri-unknown-req",
							"sharedSecret": %q,
							"permissions": ["read"],
							"requirements": ["an-unsupported-requirement"]
						}
					}
				}`, "admin@"+env.consumerHost,
					address.FormatOutgoingOCMAddressFromUserID("step14-owner", env.providerHost),
					address.FormatOutgoingOCMAddressFromUserID("step14-sender", env.providerHost),
					secret))
				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				defer resp.Body.Close()
				assertInboundStatus(t, env, resp, http.StatusNotImplemented)
				return []string{secret}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			beforeSnap, err := tsprotocol.SnapshotPersistence(env.consumer.TempDir)
			if err != nil {
				t.Fatalf("snapshot persistence before %s: %v", tc.name, err)
			}

			secrets := tc.act(t, env)

			afterSnap, err := tsprotocol.SnapshotPersistence(env.consumer.TempDir)
			if err != nil {
				t.Fatalf("snapshot persistence after %s: %v", tc.name, err)
			}
			assertInboundRejectionInvariants(t, env.consumer, recordingReceiver, beforeSnap, afterSnap, secrets)
		})
	}
}

func assertInboundRejectionInvariants(
	t *testing.T,
	consumer *harness.SubprocessServer,
	recordingReceiver *strictRecordingReceiver,
	before, after tsprotocol.PersistenceSnapshot,
	secrets []string,
) {
	t.Helper()

	assertPersistenceUnchanged(t, before, after)
	assertNoUnexpectedNetwork(t, []*harness.SubprocessServer{consumer}, allowedInboundShareRequestNeedles...)
	assertNoOutboundFallback(t, recordingReceiver, allowedInboundShareRequestNeedles, consumer)
	assertNoSecretInLogs(t, secrets, consumer)
}

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

func runMalformedDiscoveryBlocksOutboundCase(
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

	testContent := []byte("Step 14 negative shared-secret bearer proof")
	testFile := filepath.Join(t.TempDir(), "protocol-negative-bearer.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	providerToken := loginSubprocessAdminWithClient(t, provider)
	consumerHost := hostFromBaseURL(t, consumer.BaseURL)

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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(resp.Body)
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

func assertInboundStatus(t *testing.T, env inboundNegativeEnv, resp *http.Response, want int) {
	t.Helper()

	if resp.StatusCode == want {
		return
	}
	respBody, _ := io.ReadAll(resp.Body)
	env.provider.DumpLogs(t)
	env.consumer.DumpLogs(t)
	t.Fatalf("expected status %d, got %d: %s", want, resp.StatusCode, respBody)
}

func postJSONWithClient(t *testing.T, client *http.Client, targetURL string, body []byte) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", targetURL, err)
	}
	return resp
}

func buildInboundShareBodyWithOwnerSender(
	shareWith, providerID, ownerHost, senderHost, protocolName, webdavURI, sharedSecret string,
) []byte {
	owner := address.FormatOutgoingOCMAddressFromUserID("step14-owner", ownerHost)
	sender := address.FormatOutgoingOCMAddressFromUserID("step14-sender", senderHost)
	payload := spec.NewShareRequest{
		ShareWith:    shareWith,
		Name:         "step14-inbound-negative.txt",
		ProviderID:   providerID,
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: "file",
		Protocol: spec.Protocol{
			Name: protocolName,
			WebDAV: &spec.WebDAVProtocol{
				URI:          webdavURI,
				SharedSecret: sharedSecret,
				Permissions:  []string{"read"},
				Requirements: []string{spec.RequirementMustExchangeToken},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func setForeignSignatureLabelsOnly(req *http.Request) {
	foreignSigInput := `sig1=("@method" "@target-uri" "content-digest" "content-length" "date");created=1;keyid="foreign.example#k1";alg="ed25519"`
	foreignSignature := "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
	req.Header.Set("Signature-Input", foreignSigInput)
	req.Header.Set("Signature", foreignSignature)
}

func duplicateOCMSignatureLabel(req *http.Request) {
	sigInput := req.Header.Get("Signature-Input")
	sig := req.Header.Get("Signature")
	req.Header.Set("Signature-Input", sigInput+", "+sigInput)
	req.Header.Set("Signature", sig+", "+sig)
}

func writeNegativeShareFile(t *testing.T, label string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "negative-share-"+label+".txt")
	if err := os.WriteFile(path, []byte("negative integration share payload for "+label), 0644); err != nil {
		t.Fatalf("write share file: %v", err)
	}
	return path
}

type crossAuthorityDiscoveryPeer = trustedProtocolPeer

func startCrossAuthorityDiscoveryPeer(t *testing.T) *crossAuthorityDiscoveryPeer {
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

type redirectSSRFDiscoveryPeer = trustedProtocolPeer

func startRedirectSSRFDiscoveryPeer(t *testing.T) *redirectSSRFDiscoveryPeer {
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
