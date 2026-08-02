// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package directoryservice

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestCollectAlgorithms(t *testing.T) {
	keys := []VerificationKey{
		{Algorithm: "Ed25519", Active: true},
		{Algorithm: "RS256", Active: true},
		{Algorithm: "ES256", Active: true},
		{Algorithm: "Ed25519", Active: true},
		{Algorithm: "RS256", Active: false},
		{Algorithm: "unknown", Active: true},
	}

	algs := collectAlgorithms(keys)
	if len(algs) != 3 {
		t.Fatalf("expected 3 algorithms, got %d: %v", len(algs), algs)
	}

	expected := map[jose.SignatureAlgorithm]bool{jose.EdDSA: true, jose.RS256: true, jose.ES256: true}
	for _, a := range algs {
		if !expected[a] {
			t.Errorf("unexpected algorithm: %v", a)
		}
	}
}

func TestMapAlgorithm(t *testing.T) {
	cases := []struct {
		input string
		want  jose.SignatureAlgorithm
		ok    bool
	}{
		{"Ed25519", jose.EdDSA, true},
		{"ed25519", jose.EdDSA, true},
		{"EdDSA", jose.EdDSA, true},
		{"RS256", jose.RS256, true},
		{"ES256", jose.ES256, true},
		{"unknown", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		got, ok := mapAlgorithm(tc.input)
		if ok != tc.ok || got != tc.want {
			t.Errorf("mapAlgorithm(%q) = (%v, %v), want (%v, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	kp := generateEd25519(t)

	pub, err := parsePublicKey(kp.pem)
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}

	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	_, err := parsePublicKey("not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestIsValidServerURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com", true},
		{"https://example.com/", true},
		{"https://example.com:9200", true},
		{"http://example.com", true},
		{"https://example.com/base/path", false},
		{"https://user:pass@example.com", false},
		{"https://example.com?q=1", false},
		{"https://example.com#frag", false},
		{"ftp://example.com", false},
		{"not-a-url", false},
		{"", false},
		{"/relative/path", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got := isValidServerURL(tc.url)
			if got != tc.want {
				t.Errorf("isValidServerURL(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}
