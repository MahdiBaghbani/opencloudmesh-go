// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package directoryservice

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestFetchListing_Required_SetsVerifiedTrue(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !listing.Verified {
		t.Error("expected Verified=true for required policy with valid JWS")
	}
}

func TestFetchListing_Optional_UnsignedPayload_Accepted(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if listing.Verified {
		t.Error("expected Verified=false for unsigned payload with optional policy")
	}

	assertListing(t, listing)
}

func TestFetchListing_Optional_ValidJWS_Verified(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !listing.Verified {
		t.Error("expected Verified=true for valid JWS with optional policy")
	}

	assertListing(t, listing)
}

func TestFetchListing_Optional_BadSignature_Rejected(t *testing.T) {
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for bad signature with optional policy")
	}
}

func TestFetchListing_Optional_NoKeys_AcceptsAsUnsigned(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if listing.Verified {
		t.Error("expected Verified=false with no keys in optional mode")
	}

	assertListing(t, listing)
}

func TestFetchListing_Off_Accepted(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "off", nil)
	keys := []VerificationKey{}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if listing.Verified {
		t.Error("expected Verified=false for off policy")
	}

	assertListing(t, listing)
}

// TestTrustMembershipGuardrail_RequiredRejectsUnsignedListing documents that
// peer trust membership refresh uses required JWS verification (matching wiring
// bootstrap). Unsigned directory listings must not satisfy membership refresh.
func TestTrustMembershipGuardrail_RequiredRejectsUnsignedListing(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "required")
	if err == nil {
		t.Fatal("trust membership path requires JWS-verified listings; unsigned payload must fail")
	}
}

func TestFetchListing_PerCallPolicyOverridesDefault(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for unsigned payload with required default policy")
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "off")
	if err != nil {
		t.Fatalf("unexpected error with per-call off policy: %v", err)
	}

	if listing.Verified {
		t.Error("expected Verified=false for off policy")
	}
}

func TestFetchListing_URLValidation_VerifiedListingFiltersInvalidURLs(t *testing.T) {
	payload, err := json.Marshal(Listing{ //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
		Federation: "test-federation",
		Servers: []Server{
			{URL: "https://valid.example.com", DisplayName: "Valid"},
			{URL: "https://also-valid.example.com:9200", DisplayName: "Also Valid"},
			{URL: "https://also-valid.example.com/", DisplayName: "Also Valid Trailing Slash"},
			{URL: "https://has-path.example.com/base/path", DisplayName: "Has Path"},
			{URL: "https://user:pass@has-userinfo.example.com", DisplayName: "Has Userinfo"},
			{URL: "https://has-query.example.com?q=1", DisplayName: "Has Query"},
			{URL: "ftp://wrong-scheme.example.com", DisplayName: "Wrong Scheme"},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, payload)

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !listing.Verified {
		t.Error("expected Verified=true")
	}

	if len(listing.Servers) != 3 {
		t.Fatalf("expected 3 valid servers after filtering, got %d: %v", len(listing.Servers), listing.Servers)
	}

	expectedURLs := map[string]bool{
		"https://valid.example.com":           true,
		"https://also-valid.example.com:9200": true,
		"https://also-valid.example.com/":     true,
	}
	for _, s := range listing.Servers {
		if !expectedURLs[s.URL] {
			t.Errorf("unexpected server URL after filtering: %q", s.URL)
		}
	}
}

func TestTrustMembershipConsumesVerifiedListings_Guardrail(t *testing.T) {
	unsignedTS := serveJWS(t, testPayload())
	defer unsignedTS.Close()

	trustClient := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := trustClient.FetchListing(t.Context(), unsignedTS.URL, keys, "")
	if err == nil {
		t.Fatal("unsigned listing must be rejected under required policy used for trust membership")
	}

	signedBody := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	signedTS := serveJWS(t, signedBody)
	defer signedTS.Close()

	listing, err := trustClient.FetchListing(t.Context(), signedTS.URL, keys, "")
	if err != nil {
		t.Fatalf("JWS-verified listing must be accepted: %v", err)
	}

	if !listing.Verified {
		t.Fatal("trust membership consumes only JWS-verified directory listings")
	}
}

func TestFetchListing_URLValidation_UnverifiedListingKeepsAllURLs(t *testing.T) {
	payload, err := json.Marshal(Listing{ //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
		Federation: "test-federation",
		Servers: []Server{
			{URL: "https://valid.example.com", DisplayName: "Valid"},
			{URL: "https://has-path.example.com/base/path", DisplayName: "Has Path"},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	ts := serveJWS(t, payload)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if listing.Verified {
		t.Error("expected Verified=false for unsigned payload")
	}

	if len(listing.Servers) != 2 {
		t.Errorf("expected 2 servers (no filtering for unverified), got %d", len(listing.Servers))
	}
}
