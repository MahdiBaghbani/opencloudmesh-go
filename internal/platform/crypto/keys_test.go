// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func TestKeyManager_LoadOrGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "signing.pem")

	km := crypto.NewKeyManager(keyPath, "https://example.com:9200")

	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	key := km.GetSigningKey()
	if key == nil {
		t.Fatal("expected signing key to be set")
	}

	if key.Algorithm != "ed25519" {
		t.Errorf("expected algorithm ed25519, got %s", key.Algorithm)
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file should exist: %v", err)
	}

	km2 := crypto.NewKeyManager(keyPath, "https://example.com:9200")
	if err := km2.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate (reload) failed: %v", err)
	}

	pem1 := getPublicKeyPEM(km)

	pem2 := getPublicKeyPEM(km2)
	if pem1 != pem2 {
		t.Error("public keys should match after reload")
	}
}

func TestKeyManager_StableKeyID(t *testing.T) {
	tests := []struct {
		publicOrigin  string
		expectedKeyID string
	}{
		{"https://example.com", "example.com#key1"},
		{"https://example.com:443", "example.com#key1"},
		{"https://example.com:9200", "example.com:9200#key1"},
		{"http://localhost:8080", "localhost:8080#key1"},
		{"https://cloud.example.org:443", "cloud.example.org#key1"},
		{"https://example.com/", "example.com#key1"},
		{"https://EXAMPLE.COM", "example.com#key1"},
	}

	for _, tt := range tests {
		t.Run(tt.publicOrigin, func(t *testing.T) {
			km := crypto.NewKeyManager("", tt.publicOrigin)
			if km.GetKeyID() != tt.expectedKeyID {
				t.Errorf("expected keyId %q, got %q", tt.expectedKeyID, km.GetKeyID())
			}
		})
	}
}

func TestKeyManager_KeyIDUsesProviderDomain(t *testing.T) {
	id, err := localidentity.Derive("https://cloud.example.org:443", "")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	want := id.ProviderDomain + "#key1"

	km := crypto.NewKeyManager("", id.Origin)
	if km.GetKeyID() != want {
		t.Errorf("keyId = %q, want %q", km.GetKeyID(), want)
	}
}

func TestKeyManager_JWKS(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	set := km.JWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}

	if set.Keys[0].Kid != km.GetKeyID() {
		t.Fatalf("kid = %q, want %q", set.Keys[0].Kid, km.GetKeyID())
	}
}

func TestKeyManager_Sign(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	message := []byte("test message")

	sig, err := km.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("expected 64 byte signature, got %d", len(sig))
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	pem := getPublicKeyPEM(km)
	if pem == "" {
		t.Fatal("expected non-empty PEM")
	}

	pub, err := parsePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}

	key := km.GetSigningKey()
	if len(pub) != len(key.PublicKey) {
		t.Error("parsed key length mismatch")
	}
}
