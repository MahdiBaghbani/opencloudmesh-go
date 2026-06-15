// Package sigalg resolves and validates RFC 9421 HTTP signature algorithms.
package sigalg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// Ed25519 is the default asymmetric algorithm for OCM HTTP signatures.
const Ed25519 = "ed25519"

// Symmetric algorithms that MUST NOT be used for OCM HTTP signatures.
var symmetricAlgorithms = map[string]struct{}{
	"hmac-sha256": {},
	"hmac-sha384": {},
	"hmac-sha512": {},
}

// DefaultAllowed returns the default allowed asymmetric RFC 9421 algorithms.
func DefaultAllowed() []string {
	return []string{Ed25519}
}

// IsSymmetric reports whether alg is a symmetric HMAC algorithm.
func IsSymmetric(alg string) bool {
	_, ok := symmetricAlgorithms[strings.ToLower(strings.TrimSpace(alg))]
	return ok
}

// ValidateAllowed rejects symmetric algorithms and algorithms outside the
// configured allow-list.
func ValidateAllowed(alg string, allowed []string) error {
	alg = strings.ToLower(strings.TrimSpace(alg))
	if alg == "" {
		return errors.New("sigalg: missing algorithm")
	}
	if IsSymmetric(alg) {
		return fmt.Errorf("sigalg: symmetric algorithm %q is not permitted", alg)
	}

	for _, candidate := range allowed {
		if strings.ToLower(strings.TrimSpace(candidate)) == alg {
			return nil
		}
	}

	return fmt.Errorf("sigalg: algorithm %q is not allowed", alg)
}

// Sign signs message with the given algorithm and private key material.
func Sign(alg string, privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case Ed25519:
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("sigalg: ed25519 signing requires an Ed25519 private key")
		}
		return ed25519.Sign(key, message), nil
	default:
		return nil, fmt.Errorf("sigalg: signing for algorithm %q is not implemented", alg)
	}
}

// Verify verifies message signature with the given algorithm and public key.
func Verify(alg string, publicKey crypto.PublicKey, message, signature []byte) error {
	switch strings.ToLower(strings.TrimSpace(alg)) {
	case Ed25519:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("sigalg: ed25519 verification requires an Ed25519 public key")
		}
		if !ed25519.Verify(key, message, signature) {
			return errors.New("sigalg: ed25519 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("sigalg: verification for algorithm %q is not implemented", alg)
	}
}

// PublicKeyFromJWK resolves an Ed25519 public key from a base64url-encoded x
// coordinate. RSA helpers are reserved for future asymmetric algorithm support.
func PublicKeyFromJWK(kty, crv, x string) (crypto.PublicKey, error) {
	switch strings.ToUpper(strings.TrimSpace(kty)) {
	case "OKP":
		if strings.ToUpper(strings.TrimSpace(crv)) != "ED25519" {
			return nil, fmt.Errorf("sigalg: unsupported OKP curve %q", crv)
		}
		raw, err := decodeBase64URL(x)
		if err != nil {
			return nil, fmt.Errorf("sigalg: decode Ed25519 x: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sigalg: Ed25519 x must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
		}
		return ed25519.PublicKey(raw), nil
	case "RSA":
		return nil, errors.New("sigalg: RSA JWK verification is not implemented")
	default:
		return nil, fmt.Errorf("sigalg: unsupported JWK kty %q", kty)
	}
}

// SumSHA256 returns a SHA-256 digest helper for content-digest construction.
func SumSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
