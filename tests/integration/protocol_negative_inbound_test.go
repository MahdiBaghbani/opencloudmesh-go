// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

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
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-unsigned-secret"
				body := buildSignedInboundShareBody(t, "admin@"+env.consumerHost, "step14-neg-unsigned", env.providerHost, "webdav-uri-unsigned",
					secret,
				)
				actInboundSharePost(t, env, body, http.StatusUnauthorized, false)

				return []string{secret}
			},
		},
		{
			name:       "wrong_signature_authority",
			wantStatus: http.StatusForbidden,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-wrong-authority-secret"
				wrongHost := "wrong-authority.invalid"
				body := buildSignedInboundShareBody(t, "admin@"+env.consumerHost, "step14-neg-wrong-authority", wrongHost, "webdav-uri-wrong-authority",
					secret,
				)
				actInboundSharePost(t, env, body, http.StatusForbidden, true)

				return []string{secret}
			},
		},
		{
			name:       "owner_provider_mismatch",
			wantStatus: http.StatusForbidden,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-owner-mismatch-secret"
				body := buildInboundShareBodyWithOwnerSender(t,
					"admin@"+env.consumerHost,
					"step14-neg-owner-mismatch",
					"foreign-owner.invalid",
					env.providerHost,
					"webdav",
					"webdav-uri-owner-mismatch",
					secret,
				)
				actInboundSharePost(t, env, body, http.StatusForbidden, true)

				return []string{secret}
			},
		},
		{
			name:       "foreign_labels_without_ocm_signature",
			wantStatus: http.StatusUnauthorized,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-foreign-labels-secret"
				body := buildInboundShareBodyWithOwnerSender(t,
					"admin@"+env.consumerHost,
					"step14-neg-foreign-labels",
					env.providerHost,
					env.providerHost,
					"webdav",
					"webdav-uri-foreign-labels",
					secret,
				)
				actInboundForeignLabelsPost(t, env, body, http.StatusUnauthorized)

				return []string{secret}
			},
		},
		{
			name:       "duplicate_ocm_signature",
			wantStatus: http.StatusUnauthorized,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-duplicate-ocm-secret"
				body := buildSignedInboundShareBody(t, "admin@"+env.consumerHost, "step14-neg-duplicate-ocm", env.providerHost, "webdav-uri-duplicate-ocm",
					secret,
				)
				actInboundDuplicateLabelPost(t, env, body, http.StatusUnauthorized)

				return []string{secret}
			},
		},
		{
			name:       "invalid_protocol_structure",
			wantStatus: http.StatusBadRequest,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-invalid-structure-secret"
				protocolJSON := fmt.Sprintf(`{
					"webdav": {
						"uri": "webdav-uri-invalid-structure",
						"sharedSecret": %q,
						"permissions": ["read"],
						"requirements": ["must-exchange-token"]
					}
				}`, secret)
				body := buildInboundRawProtocolBody(env, "step14-neg-invalid-structure.txt", "step14-neg-invalid-structure", protocolJSON)
				actInboundSharePost(t, env, body, http.StatusBadRequest, true)

				return []string{secret}
			},
		},
		{
			name:       "unsupported_protocol_arm",
			wantStatus: http.StatusNotImplemented,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-unsupported-arm-secret"
				protocolJSON := fmt.Sprintf(`{
					"name": "webdav",
					"webdav": {
						"uri": "webdav-uri-unsupported-arm",
						"sharedSecret": %q,
						"permissions": ["read"],
						"requirements": ["must-exchange-token"]
					},
					"datatx": {}
				}`, secret)
				body := buildInboundRawProtocolBody(env, "step14-neg-unsupported-arm.txt", "step14-neg-unsupported-arm", protocolJSON)
				actInboundSharePost(t, env, body, http.StatusNotImplemented, true)

				return []string{secret}
			},
		},
		{
			name:       "unknown_requirement",
			wantStatus: http.StatusNotImplemented,
			act: func(t *testing.T, env inboundNegativeEnv) []string { //nolint:thelper // table act closure, not a reusable helper
				secret := "step14-neg-unknown-req-secret"
				protocolJSON := fmt.Sprintf(`{
					"name": "webdav",
					"webdav": {
						"uri": "webdav-uri-unknown-req",
						"sharedSecret": %q,
						"permissions": ["read"],
						"requirements": ["an-unsupported-requirement"]
					}
				}`, secret)
				body := buildInboundRawProtocolBody(env, "step14-neg-unknown-req.txt", "step14-neg-unknown-req", protocolJSON)
				actInboundSharePost(t, env, body, http.StatusNotImplemented, true)

				return []string{secret}
			},
		},
	}

	for _, tc := range cases {
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

func assertInboundStatus(t *testing.T, env inboundNegativeEnv, resp *http.Response, want int) {
	t.Helper()

	if resp.StatusCode == want {
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	env.provider.DumpLogs(t)
	env.consumer.DumpLogs(t)
	t.Fatalf("expected status %d, got %d: %s", want, resp.StatusCode, respBody)
}

// actInboundSharePost posts the body to /ocm/shares on the consumer, signed
// or unsigned, and asserts the expected rejection status.
func actInboundSharePost(t *testing.T, env inboundNegativeEnv, body []byte, wantStatus int, signed bool) {
	t.Helper()

	var resp *http.Response

	if signed {
		resp = postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	} else {
		resp = postJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	}

	defer tshttp.MustClose(t, resp.Body)

	assertInboundStatus(t, env, resp, wantStatus)
}

// actInboundForeignLabelsPost posts with foreign signature labels only (no
// ocm signature) and asserts the expected rejection status.
func actInboundForeignLabelsPost(t *testing.T, env inboundNegativeEnv, body []byte, wantStatus int) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		env.consumer.BaseURL+"/ocm/shares",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("build POST with foreign labels only: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	setForeignSignatureLabelsOnly(req)

	resp, err := env.consumer.Client().Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("POST with foreign labels only: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	assertInboundStatus(t, env, resp, wantStatus)
}

// actInboundDuplicateLabelPost signs the request, duplicates the ocm
// signature label, and asserts the expected rejection status.
func actInboundDuplicateLabelPost(t *testing.T, env inboundNegativeEnv, body []byte, wantStatus int) {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		env.consumer.BaseURL+"/ocm/shares",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("build signed POST: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if signErr := env.signer.SignRequest(req, body); signErr != nil {
		t.Fatalf("sign POST: %v", signErr)
	}

	duplicateOCMSignatureLabel(req)

	resp, err := env.consumer.Client().Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("signed POST with duplicate ocm label: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	assertInboundStatus(t, env, resp, wantStatus)
}

// buildInboundRawProtocolBody builds a share request body with a raw protocol
// JSON arm for negative structure/requirement cases.
func buildInboundRawProtocolBody(env inboundNegativeEnv, name, providerID, protocolJSON string) []byte {
	return fmt.Appendf(nil, `{
		"shareWith": %q,
		"name": %q,
		"providerId": %q,
		"owner": %q,
		"sender": %q,
		"shareType": "user",
		"resourceType": "file",
		"protocol": %s
	}`, "admin@"+env.consumerHost,
		name,
		providerID,
		address.FormatOutgoingOCMAddressFromUserID("step14-owner", env.providerHost),
		address.FormatOutgoingOCMAddressFromUserID("step14-sender", env.providerHost),
		protocolJSON)
}

func postJSONWithClient(t *testing.T, client *http.Client, targetURL string, body []byte) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
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
	t *testing.T,
	shareWith, providerID, ownerHost, senderHost, protocolName, webdavURI, sharedSecret string,
) []byte {
	t.Helper()

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

	return tshttp.MustMarshalJSON(t, payload)
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
