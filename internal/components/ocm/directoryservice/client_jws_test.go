// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package directoryservice

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func newTestHTTPClient() *httpclient.Client {
	cfg := tshttp.PermissiveConfig()
	cfg.MaxRedirects = 0

	return httpclient.New(cfg, nil)
}

func TestFetchListing_CompactJWS_Ed25519(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_CompactJWS_RS256(t *testing.T) {
	t.Parallel()
	kp := generateRSA(t)
	body := signCompact(t, jose.RS256, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "RS256", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_CompactJWS_ES256(t *testing.T) {
	t.Parallel()
	kp := generateECDSA(t)
	body := signCompact(t, jose.ES256, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "ES256", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_FlattenedJSON_Ed25519(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signFullSerialize(t, jose.EdDSA, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_GeneralJSON_MultipleSignatures(t *testing.T) {
	t.Parallel()
	kp1 := generateEd25519(t)
	kp2 := generateRSA(t)

	ms, err := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.EdDSA, Key: kp1.priv},
		{Algorithm: jose.RS256, Key: kp2.priv},
	}, nil)
	if err != nil {
		t.Fatalf("create multi-signer: %v", err)
	}

	jws, err := ms.Sign(testPayload(t))
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	body := []byte(jws.FullSerialize())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{
		{KeyID: "k1", PublicKeyPEM: kp1.pem, Algorithm: "Ed25519", Active: true},
		{KeyID: "k2", PublicKeyPEM: kp2.pem, Algorithm: "RS256", Active: true},
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_InvalidSignature(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload(t))

	bodyStr := string(body)
	bodyStr = bodyStr[:len(bodyStr)-4] + "XXXX"

	ts := serveJWS(t, []byte(bodyStr))
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected verification error, got nil")
	}
}

func TestFetchListing_WrongKey(t *testing.T) {
	t.Parallel()
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected verification error for wrong key, got nil")
	}
}

func TestFetchListing_InactiveKey(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: false}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for inactive key, got nil")
	}
}

func TestFetchListing_MissingFederationField(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)

	payload, err := json.Marshal(map[string]any{
		"servers": []map[string]string{{"url": "https://a.example.com", "displayName": "A"}},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	body := signCompact(t, jose.EdDSA, kp.priv, payload)

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err = client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for missing federation field, got nil")
	}
}

func TestFetchListing_UnsignedPayload(t *testing.T) {
	t.Parallel()

	ts := serveJWS(t, testPayload(t))
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for unsigned payload, got nil")
	}
}

func TestFetchListing_NoActiveKeys(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for no active keys, got nil")
	}
}

func TestFetchListing_MultipleKeys_SecondMatches(t *testing.T) {
	t.Parallel()
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{
		{KeyID: "wrong", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true},
		{KeyID: "correct", PublicKeyPEM: signing.pem, Algorithm: "Ed25519", Active: true},
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_AlgorithmCaseInsensitive(t *testing.T) {
	t.Parallel()
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload(t))

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertListing(t, listing)
}

func TestFetchListing_HTTPError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}
