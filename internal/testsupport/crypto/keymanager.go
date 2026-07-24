package crypto

import (
	"testing"

	platformcrypto "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

// MustTestKeyManager returns a KeyManager with keys loaded or generated for origin.
func MustTestKeyManager(t testing.TB, origin string) *platformcrypto.KeyManager {
	t.Helper()
	km := platformcrypto.NewKeyManager("", origin)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate origin=%q: %v", origin, err)
	}
	return km
}

// NewTestKeyManager returns a KeyManager without loading keys (ID-only tests).
func NewTestKeyManager(origin string) *platformcrypto.KeyManager {
	return platformcrypto.NewKeyManager("", origin)
}

// MustTestKeyManagerWithPath returns a KeyManager loaded from or persisted to keyPath.
func MustTestKeyManagerWithPath(t testing.TB, keyPath, origin string) *platformcrypto.KeyManager {
	t.Helper()
	km := platformcrypto.NewKeyManager(keyPath, origin)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate keyPath=%q origin=%q: %v", keyPath, origin, err)
	}
	return km
}
