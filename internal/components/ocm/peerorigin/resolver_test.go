// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package peerorigin

import "testing"

func TestResolve_StrictDefaultIsHTTPS(t *testing.T) {
	r := NewResolver(false)

	decision := r.Resolve("peer.example.com")
	if decision.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", decision.Scheme)
	}

	if decision.BaseURL != "https://peer.example.com" {
		t.Fatalf("baseURL = %q, want https://peer.example.com", decision.BaseURL)
	}

	if decision.PeerDomain != "peer.example.com" {
		t.Fatalf("peerDomain = %q, want peer.example.com", decision.PeerDomain)
	}

	if decision.AllowHTTP {
		t.Fatal("expected AllowHTTP to be false with dev flag disabled")
	}
}

func TestResolve_DevFlagHonorsExplicitHTTPSPeerInput(t *testing.T) {
	r := NewResolver(true)

	decision := r.Resolve("https://strict.example.com:8443")
	if decision.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", decision.Scheme)
	}

	if decision.BaseURL != "https://strict.example.com:8443" {
		t.Fatalf("baseURL = %q, want https://strict.example.com:8443", decision.BaseURL)
	}

	if decision.PeerDomain != "strict.example.com:8443" {
		t.Fatalf("peerDomain = %q, want strict.example.com:8443", decision.PeerDomain)
	}
}

func TestResolve_DevFlagAllowsHTTPForEveryPeer(t *testing.T) {
	r := NewResolver(true)

	first := r.Resolve("first.example.com")
	if first.Scheme != "http" {
		t.Fatalf("first peer scheme = %q, want http", first.Scheme)
	}

	if first.BaseURL != "http://first.example.com" {
		t.Fatalf("first peer baseURL = %q, want http://first.example.com", first.BaseURL)
	}

	if !first.AllowHTTP {
		t.Fatal("expected AllowHTTP to be true with dev flag enabled")
	}

	second := r.Resolve("second.example.com")
	if second.Scheme != "http" {
		t.Fatalf("second peer scheme = %q, want http", second.Scheme)
	}

	if !second.AllowHTTP {
		t.Fatal("expected AllowHTTP to be true for every peer with dev flag enabled")
	}
}

func TestResolve_EmptyInputResolvesToZeroDecision(t *testing.T) {
	r := NewResolver(true)

	decision := r.Resolve("")
	if decision != (Decision{}) {
		t.Fatalf("decision = %+v, want zero value", decision)
	}
}

func TestResolve_NilResolverIsStrict(t *testing.T) {
	var r *Resolver

	decision := r.Resolve("peer.example.com")
	if decision.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", decision.Scheme)
	}

	if decision.AllowHTTP {
		t.Fatal("expected a nil resolver to never allow HTTP")
	}
}

func TestIsAbsoluteURIAllowed_EnforcesHTTPGate(t *testing.T) {
	strict := NewResolver(false)

	if strict.IsAbsoluteURIAllowed(
		"http://peer.example.com/webdav/file.txt",
		"peer.example.com",
	) {
		t.Fatal("expected http absolute URI to be rejected without the dev-mode flag")
	}

	if !strict.IsAbsoluteURIAllowed(
		"https://peer.example.com/webdav/file.txt",
		"peer.example.com",
	) {
		t.Fatal("expected https absolute URI to remain valid without the dev-mode flag")
	}

	dev := NewResolver(true)

	if !dev.IsAbsoluteURIAllowed(
		"http://peer.example.com/webdav/file.txt",
		"peer.example.com",
	) {
		t.Fatal("expected http absolute URI to be accepted with the dev-mode flag enabled")
	}

	if !dev.IsAbsoluteURIAllowed(
		"https://peer.example.com/webdav/file.txt",
		"peer.example.com",
	) {
		t.Fatal("expected https absolute URI to remain valid with the dev-mode flag enabled")
	}
}

func TestIsAbsoluteURIAllowed_AuthorityMismatchRejected(t *testing.T) {
	r := NewResolver(true)

	if r.IsAbsoluteURIAllowed(
		"http://other.example.com/webdav/file.txt",
		"peer.example.com",
	) {
		t.Fatal("expected absolute URI authority mismatch to be rejected")
	}
}

func TestIsAbsoluteURIAllowed_RejectsUnparsableOrNonHTTPScheme(t *testing.T) {
	r := NewResolver(true)

	if r.IsAbsoluteURIAllowed("://not-a-valid-url", "peer.example.com") {
		t.Fatal("expected unparsable absolute URI to be rejected")
	}

	if r.IsAbsoluteURIAllowed("ftp://peer.example.com/file.txt", "peer.example.com") {
		t.Fatal("expected non-HTTP(S) scheme to be rejected")
	}
}
