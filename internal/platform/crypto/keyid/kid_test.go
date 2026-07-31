// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package keyid_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
)

func TestBuildKid(t *testing.T) {
	got := keyid.BuildKid("example.com", "key1")
	if got != "example.com#key1" {
		t.Fatalf("BuildKid = %q", got)
	}
}

func TestParseKid_HostFragment(t *testing.T) {
	parsed, err := keyid.ParseKid("example.com#key1")
	if err != nil {
		t.Fatalf("ParseKid: %v", err)
	}

	if parsed.Authority != "example.com" || parsed.Fragment != "key1" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestKidFromPublicOrigin(t *testing.T) {
	got, err := keyid.KidFromPublicOrigin("https://example.com:9200", "key1")
	if err != nil {
		t.Fatalf("KidFromPublicOrigin: %v", err)
	}

	if got != "example.com:9200#key1" {
		t.Fatalf("kid = %q", got)
	}
}

func TestParseKid_AbsoluteURI(t *testing.T) {
	parsed, err := keyid.ParseKid("https://example.com/ocm#key-1")
	if err != nil {
		t.Fatalf("ParseKid: %v", err)
	}

	if parsed.Fragment != "key-1" {
		t.Fatalf("Fragment = %q", parsed.Fragment)
	}

	if parsed.Authority != "example.com" {
		t.Fatalf("Authority = %q", parsed.Authority)
	}
}

func TestParseKid_RejectsPathfulHostFragment(t *testing.T) {
	if _, err := keyid.ParseKid("example.com/ocm#key1"); err == nil {
		t.Fatal("expected pathful host#fragment to be rejected")
	}
}

func TestCanonicalJWKSAuthority(t *testing.T) {
	hostFrag, err := keyid.ParseKid("Example.COM:443#key1")
	if err != nil {
		t.Fatalf("ParseKid: %v", err)
	}

	scheme, authority, err := keyid.CanonicalJWKSAuthority(hostFrag)
	if err != nil {
		t.Fatalf("CanonicalJWKSAuthority: %v", err)
	}

	if scheme != "https" || authority != "example.com" {
		t.Fatalf("host#fragment = %s %q, want https example.com", scheme, authority)
	}

	abs, err := keyid.ParseKid("https://Example.COM:443/ocm#key1")
	if err != nil {
		t.Fatalf("ParseKid URI: %v", err)
	}

	scheme, authority, err = keyid.CanonicalJWKSAuthority(abs)
	if err != nil {
		t.Fatalf("CanonicalJWKSAuthority URI: %v", err)
	}

	if scheme != "https" || authority != "example.com" {
		t.Fatalf("absolute URI = %s %q, want https example.com", scheme, authority)
	}
}
