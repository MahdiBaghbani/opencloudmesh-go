// Package crypto provides cryptographic primitives for OCM signatures.
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// SigningKey holds an Ed25519 keypair for RFC 9421 signatures.
type SigningKey struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	KeyID      string // URI format: https://example.com/ocm#key-1
	Algorithm  string // ed25519
}

// KeyManager manages signing keys for an OCM instance.
type KeyManager struct {
	mu         sync.RWMutex
	signingKey *SigningKey
	keyPath    string // path to persist private key
	keyID      string // stable keyId derived from external_origin
}

// NewKeyManager creates a new key manager.
// keyPath is where the private key is stored. keyID is derived from external_origin.
func NewKeyManager(keyPath, externalOrigin string) *KeyManager {
	// Derive stable keyId from external_origin
	keyID := deriveKeyID(externalOrigin)
	return &KeyManager{
		keyPath: keyPath,
		keyID:   keyID,
	}
}

// deriveKeyID creates a stable keyId URI from external_origin.
func deriveKeyID(externalOrigin string) string {
	// Parse to ensure it's a valid URL
	u, err := url.Parse(externalOrigin)
	if err != nil {
		// Fall back to simple construction
		return externalOrigin + "/ocm#key-1"
	}

	// Construct stable keyId: scheme://host/ocm#key-1
	return fmt.Sprintf("%s://%s/ocm#key-1", u.Scheme, u.Host)
}

// LoadOrGenerate loads existing key from disk or generates a new one.
func (km *KeyManager) LoadOrGenerate() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Try to load existing key
	if km.keyPath != "" {
		if key, err := km.loadKey(); err == nil {
			km.signingKey = key
			return nil
		}
	}

	// Generate new key
	key, err := km.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}
	km.signingKey = key

	// Persist if path is set
	if km.keyPath != "" {
		if err := km.saveKey(); err != nil {
			return fmt.Errorf("failed to save signing key: %w", err)
		}
	}

	return nil
}

// generateKey creates a new Ed25519 keypair.
func (km *KeyManager) generateKey() (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      km.keyID,
		Algorithm:  "ed25519",
	}, nil
}

// loadKey loads the private key from disk.
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

	return &SigningKey{
		PrivateKey: edPriv,
		PublicKey:  edPriv.Public().(ed25519.PublicKey),
		KeyID:      km.keyID,
		Algorithm:  "ed25519",
	}, nil
}

// saveKey saves the private key to disk.
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

// GetSigningKey returns the current signing key.
func (km *KeyManager) GetSigningKey() *SigningKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.signingKey
}

// GetPublicKeyPEM returns the public key in PEM format.
func (km *KeyManager) GetPublicKeyPEM() string {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.signingKey == nil {
		return ""
	}

	pkix, err := x509.MarshalPKIXPublicKey(km.signingKey.PublicKey)
	if err != nil {
		return ""
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	}

	return string(pem.EncodeToMemory(block))
}

// GetKeyID returns the stable keyId.
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

	return km.signingKey.PrivateKey.Sign(rand.Reader, message, crypto.Hash(0))
}

// ParsePublicKeyPEM parses a PEM-encoded public key.
func ParsePublicKeyPEM(pemData string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return edPub, nil
}

// ExtractHostFromKeyID parses a keyId URI and returns the host.
func ExtractHostFromKeyID(keyID string) (string, error) {
	u, err := url.Parse(keyID)
	if err != nil {
		return "", fmt.Errorf("invalid keyId URI: %w", err)
	}

	if u.Host == "" {
		return "", errors.New("keyId has no host")
	}

	return strings.ToLower(u.Host), nil
}
