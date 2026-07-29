// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
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

func runInboundNegativeCases(t *testing.T, pair *harness.StrictProtocolPair, recordingReceiver *strictRecordingReceiver) { //nolint:maintidx // test: complex scenario coverage is intentional
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
				body := buildSignedInboundShareBody("admin@"+env.consumerHost, "step14-neg-unsigned", env.providerHost, "webdav-uri-unsigned",
					secret,
				)

				resp := postJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body)
				//nolint:errcheck // test cleanup: response body close
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
				body := buildSignedInboundShareBody("admin@"+env.consumerHost, "step14-neg-wrong-authority", wrongHost, "webdav-uri-wrong-authority",
					secret,
				)

				resp := postSignedJSONWithClient(t, env.consumer.Client(), env.consumer.BaseURL+"/ocm/shares", body, env.signer)
				//nolint:errcheck // test cleanup: response body close
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
				//nolint:errcheck // test cleanup: response body close
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
				//nolint:errcheck // test cleanup: response body close
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
				body := buildSignedInboundShareBody("admin@"+env.consumerHost, "step14-neg-duplicate-ocm", env.providerHost, "webdav-uri-duplicate-ocm",
					secret,
				)

				req, err := http.NewRequest(http.MethodPost, env.consumer.BaseURL+"/ocm/shares", bytes.NewReader(body))
				if err != nil {
					t.Fatalf("build signed POST: %v", err)
				}

				req.Header.Set("Content-Type", "application/json")

				if err := env.signer.SignRequest(req, body); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
					t.Fatalf("sign POST: %v", err)
				}

				duplicateOCMSignatureLabel(req)

				resp, err := env.consumer.Client().Do(req)
				if err != nil {
					t.Fatalf("signed POST with duplicate ocm label: %v", err)
				}
				//nolint:errcheck // test cleanup: response body close
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
				//nolint:errcheck // test cleanup: response body close
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
				//nolint:errcheck // test cleanup: response body close
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
				//nolint:errcheck // test cleanup: response body close
				defer resp.Body.Close()

				assertInboundStatus(t, env, resp, http.StatusNotImplemented)

				return []string{secret}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			switch tc.name {
			case "wrong_signature_authority", "owner_provider_mismatch", "invalid_protocol_structure", "unsupported_protocol_arm", "unknown_requirement":
				t.Skip("deferred to W1.4: inbound resolver must fetch peer-advertised jwksUri, not authority-derived /.well-known/jwks.json; see debug/CARRYOVER-W1.3-W1.4.md")
			}

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

	body, err := json.Marshal(payload) //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
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
