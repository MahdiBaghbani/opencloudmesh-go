// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package crypto provides cryptographic primitives for OCM signatures.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

// SigningKey holds an Ed25519 keypair for RFC 9421 signatures.
type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string // host#fragment kid, e.g. example.com#key1
	Algorithm  string // ed25519
}

// KeyManager manages signing keys for an OCM instance.
type KeyManager struct {
	mu         sync.RWMutex
	signingKey *SigningKey
	keyPath    string
	keyID      string
}

// NewKeyManager creates a key manager with the default kid fragment.
func NewKeyManager(keyPath, publicOrigin string) *KeyManager {
	return NewKeyManagerWithFragment(keyPath, publicOrigin, keyid.DefaultFragment)
}

// NewKeyManagerWithFragment creates a key manager using an explicit kid fragment.
func NewKeyManagerWithFragment(keyPath, publicOrigin, kidFragment string) *KeyManager {
	keyID, err := keyid.KidFromPublicOrigin(publicOrigin, kidFragment)
	if err != nil {
		keyID = keyid.BuildKid(publicOrigin, kidFragment)
	}

	return &KeyManager{
		keyPath: keyPath,
		keyID:   keyID,
	}
}

// LoadOrGenerate loads existing key from disk or generates a new one.
func (km *KeyManager) LoadOrGenerate() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.keyPath != "" {
		if key, err := km.loadKey(); err == nil {
			km.signingKey = key
			return nil
		}
	}

	key, err := km.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	km.signingKey = key

	if km.keyPath != "" {
		if err := km.saveKey(); err != nil {
			return fmt.Errorf("failed to save signing key: %w", err)
		}
	}

	return nil
}

func (km *KeyManager) generateKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      km.keyID,
		Algorithm:  sigalg.Ed25519,
	}, nil
}

func (km *KeyManager) loadKey() (*SigningKey, error) {
	data, err := os.ReadFile(km.keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}

	publicKey, ok := edPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Ed25519 public key type assertion failed")
	}

	return &SigningKey{
		PrivateKey: edPriv,
		PublicKey:  publicKey,
		KeyID:      km.keyID,
		Algorithm:  sigalg.Ed25519,
	}, nil
}

func (km *KeyManager) saveKey() error {
	if km.signingKey == nil {
		return errors.New("no signing key to save")
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(km.signingKey.PrivateKey)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}

	data := pem.EncodeToMemory(block)

	return os.WriteFile(km.keyPath, data, 0600)
}

// SetWireKeyID updates the keyId used for signatures and JWKS after
// LoadOrGenerate. It does not rotate keys or change the on-disk key path.
func (km *KeyManager) SetWireKeyID(keyID string) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.signingKey != nil {
		km.signingKey.KeyID = keyID
	}
}

// GetSigningKey returns the current signing key.
func (km *KeyManager) GetSigningKey() *SigningKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.signingKey
}

// JWKS returns the local public key set served at the OCM root /jwks route.
func (km *KeyManager) JWKS() jwks.Set {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.signingKey == nil {
		return jwks.Set{Keys: []jwks.Key{}}
	}

	return jwks.SetFromEd25519PublicKey(km.signingKey.KeyID, km.signingKey.PublicKey)
}

// GetKeyID returns the stable host#fragment kid.
func (km *KeyManager) GetKeyID() string {
	return km.keyID
}

// Sign signs a message using the signing key.
func (km *KeyManager) Sign(message []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.signingKey == nil {
		return nil, errors.New("no signing key available")
	}

	return sigalg.Sign(km.signingKey.Algorithm, km.signingKey.PrivateKey, message)
}
