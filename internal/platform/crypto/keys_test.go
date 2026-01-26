package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func TestKeyManager_LoadOrGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "signing.pem")

	km := crypto.NewKeyManager(keyPath, "https://example.com:9200")

	// First call should generate a key
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

	// Key should be persisted
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file should exist: %v", err)
	}

	// Second call with new KeyManager should load the same key
	km2 := crypto.NewKeyManager(keyPath, "https://example.com:9200")
	if err := km2.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate (reload) failed: %v", err)
	}

	key2 := km2.GetSigningKey()
	if key2 == nil {
		t.Fatal("expected signing key to be set after reload")
	}

	// Public keys should match
	pem1 := km.GetPublicKeyPEM()
	pem2 := km2.GetPublicKeyPEM()
	if pem1 != pem2 {
		t.Error("public keys should match after reload")
	}
}

func TestKeyManager_StableKeyID(t *testing.T) {
	tests := []struct {
		externalOrigin string
		expectedKeyID  string
	}{
		{"https://example.com", "https://example.com/ocm#key-1"},
		{"https://example.com:443", "https://example.com:443/ocm#key-1"},
		{"https://example.com:9200", "https://example.com:9200/ocm#key-1"},
		{"http://localhost:8080", "http://localhost:8080/ocm#key-1"},
		// Default-port preservation: :443 is NOT stripped from the emitted keyId
		{"https://cloud.example.org:443", "https://cloud.example.org:443/ocm#key-1"},
		// Trailing slash is normalized away
		{"https://example.com/", "https://example.com/ocm#key-1"},
		// Uppercase host is lowercased
		{"https://EXAMPLE.COM", "https://example.com/ocm#key-1"},
	}

	for _, tt := range tests {
		t.Run(tt.externalOrigin, func(t *testing.T) {
			km := crypto.NewKeyManager("", tt.externalOrigin)
			if km.GetKeyID() != tt.expectedKeyID {
				t.Errorf("expected keyId %q, got %q", tt.expectedKeyID, km.GetKeyID())
			}
		})
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

	if len(sig) != 64 { // Ed25519 signature is 64 bytes
		t.Errorf("expected 64 byte signature, got %d", len(sig))
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	pem := km.GetPublicKeyPEM()
	if pem == "" {
		t.Fatal("expected non-empty PEM")
	}

	pub, err := crypto.ParsePublicKeyPEM(pem)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}

	// Verify it matches the original
	key := km.GetSigningKey()
	if len(pub) != len(key.PublicKey) {
		t.Error("parsed key length mismatch")
	}
}

func TestExtractHostFromKeyID(t *testing.T) {
	tests := []struct {
		keyID    string
		expected string
		wantErr  bool
	}{
		{"https://example.com/ocm#key-1", "example.com", false},
		{"https://EXAMPLE.COM/ocm#key-1", "example.com", false},
		{"https://example.com:9200/ocm#key-1", "example.com:9200", false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.keyID, func(t *testing.T) {
			host, err := crypto.ExtractHostFromKeyID(tt.keyID)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if host != tt.expected {
					t.Errorf("expected %q, got %q", tt.expected, host)
				}
			}
		})
	}
}
