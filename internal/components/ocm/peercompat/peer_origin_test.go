// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import "testing"

func TestResolvePeerOrigin_AllowHTTPOnlyForMappedPeers(t *testing.T) {
	custom := map[string]*Profile{
		"dev-http": {
			Name:      "dev-http",
			AllowHTTP: true,
		},
	}
	mappings := []ProfileMapping{
		{Pattern: "mapped.example.com", Profile: "dev-http"},
	}

	contract, err := NewCompiledContract(custom, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	mapped := contract.ResolvePeerOrigin("mapped.example.com")
	if mapped.Scheme != "http" {
		t.Fatalf("mapped peer scheme = %q, want http", mapped.Scheme)
	}
	if mapped.BaseURL != "http://mapped.example.com" {
		t.Fatalf("mapped peer baseURL = %q, want http://mapped.example.com", mapped.BaseURL)
	}
	if !mapped.AllowHTTP {
		t.Fatal("expected mapped peer to allow HTTP")
	}

	unmapped := contract.ResolvePeerOrigin("unmapped.example.com")
	if unmapped.Scheme != "https" {
		t.Fatalf("unmapped peer scheme = %q, want https", unmapped.Scheme)
	}
	if unmapped.BaseURL != "https://unmapped.example.com" {
		t.Fatalf("unmapped peer baseURL = %q, want https://unmapped.example.com", unmapped.BaseURL)
	}
	if unmapped.AllowHTTP {
		t.Fatal("expected unmapped peer to keep HTTP disabled")
	}
}

func TestIsPeerAbsoluteURIAllowed_EnforcesHTTPGate(t *testing.T) {
	custom := map[string]*Profile{
		"dev-http": {
			Name:      "dev-http",
			AllowHTTP: true,
		},
	}
	mappings := []ProfileMapping{
		{Pattern: "mapped.example.com", Profile: "dev-http"},
	}

	contract, err := NewCompiledContract(custom, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}

	if contract.IsPeerAbsoluteURIAllowed(
		"http://unmapped.example.com/webdav/file.txt",
		"unmapped.example.com",
	) {
		t.Fatal("expected http absolute URI to be rejected for unmapped strict peer")
	}

	if !contract.IsPeerAbsoluteURIAllowed(
		"http://mapped.example.com/webdav/file.txt",
		"mapped.example.com",
	) {
		t.Fatal("expected mapped allow_http peer to accept http absolute URI")
	}

	if !contract.IsPeerAbsoluteURIAllowed(
		"https://mapped.example.com/webdav/file.txt",
		"mapped.example.com",
	) {
		t.Fatal("expected mapped allow_http peer to keep https absolute URI valid")
	}
}
