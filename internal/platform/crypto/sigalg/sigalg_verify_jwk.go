// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigalg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// Verify verifies message signature with the given algorithm and public key.
func Verify(alg string, publicKey crypto.PublicKey, message, signature []byte) error {
	native, err := Normalize(alg)
	if err != nil {
		return err
	}

	switch native {
	case Ed25519:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || key == nil {
			return fmt.Errorf("%w: expected ed25519.PublicKey", ErrWrongKeyType)
		}

		if !ed25519.Verify(key, message, signature) {
			return ErrVerifyFailed
		}

		return nil
	case ECDSAP256SHA256:
		return verifyECDSA(publicKey, elliptic.P256(), sha256.New, 32, message, signature)
	case ECDSAP384SHA384:
		return verifyECDSA(publicKey, elliptic.P384(), sha512.New384, 48, message, signature)
	case RSAPKCS1SHA256:
		return verifyRSAPKCS1(publicKey, crypto.SHA256, sha256.New, message, signature)
	case RSAPKCS1SHA384:
		return verifyRSAPKCS1(publicKey, crypto.SHA384, sha512.New384, message, signature)
	case RSAPKCS1SHA512:
		return verifyRSAPKCS1(publicKey, crypto.SHA512, sha512.New, message, signature)
	default:
		return fmt.Errorf("%w: verification for %q", ErrNotImplemented, native)
	}
}

func verifyECDSA(
	publicKey crypto.PublicKey,
	curve elliptic.Curve,
	newHash func() hash.Hash,
	coordSize int,
	message, signature []byte,
) error {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || key == nil {
		return fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrWrongKeyType)
	}

	if key.Curve != curve {
		got := "nil"
		if key.Curve != nil {
			got = key.Curve.Params().Name
		}

		return fmt.Errorf("%w: got %s want %s", ErrCurveMismatch, got, curve.Params().Name)
	}

	if len(signature) != coordSize*2 {
		return fmt.Errorf("%w: ecdsa raw r||s must be %d bytes, got %d", ErrInvalidSignatureEncoding, coordSize*2, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:coordSize])
	s := new(big.Int).SetBytes(signature[coordSize:])
	h := newHash()

	if _, err := h.Write(message); err != nil {
		return fmt.Errorf("%w: failed to hash message: %w", ErrVerifyFailed, err)
	}

	if !ecdsa.Verify(key, h.Sum(nil), r, s) {
		return ErrVerifyFailed
	}

	return nil
}

func verifyRSAPKCS1(
	publicKey crypto.PublicKey,
	hash crypto.Hash,
	newHash func() hash.Hash,
	message, signature []byte,
) error {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok || key == nil {
		return fmt.Errorf("%w: expected *rsa.PublicKey", ErrWrongKeyType)
	}

	h := newHash()

	if _, err := h.Write(message); err != nil {
		return fmt.Errorf("%w: failed to hash message: %w", ErrVerifyFailed, err)
	}

	if err := rsa.VerifyPKCS1v15(key, hash, h.Sum(nil), signature); err != nil {
		return ErrVerifyFailed
	}

	return nil
}

// JWKPublicKeyFields holds the JWK material needed to build a public key.
type JWKPublicKeyFields struct {
	Kty string
	Crv string
	Alg string
	X   string
	Y   string
	N   string
	E   string
}

// PublicKeyFromJWKFields resolves a public key from JWK fields.
func PublicKeyFromJWKFields(f JWKPublicKeyFields) (crypto.PublicKey, error) {
	switch strings.ToUpper(strings.TrimSpace(f.Kty)) {
	case "OKP":
		return publicKeyFromOKPFields(f)
	case "EC":
		return publicKeyFromECFields(f)
	case "RSA":
		return publicKeyFromRSAFields(f)
	default:
		return nil, fmt.Errorf("sigalg: unsupported JWK kty %q", f.Kty)
	}
}

func publicKeyFromOKPFields(f JWKPublicKeyFields) (crypto.PublicKey, error) {
	if !strings.EqualFold(strings.TrimSpace(f.Crv), "Ed25519") {
		return nil, fmt.Errorf("sigalg: unsupported OKP curve %q", f.Crv)
	}

	raw, err := decodeBase64URL(f.X)
	if err != nil {
		return nil, fmt.Errorf("sigalg: decode Ed25519 x: %w", err)
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sigalg: Ed25519 x must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}

	return ed25519.PublicKey(raw), nil
}

func publicKeyFromECFields(f JWKPublicKeyFields) (crypto.PublicKey, error) {
	curve, ecdhCurve, _, coordSize, err := ecParamsFromCrv(f.Crv)
	if err != nil {
		return nil, err
	}

	xRaw, err := decodeBase64URL(f.X)
	if err != nil {
		return nil, fmt.Errorf("sigalg: decode EC x: %w", err)
	}

	yRaw, err := decodeBase64URL(f.Y)
	if err != nil {
		return nil, fmt.Errorf("sigalg: decode EC y: %w", err)
	}

	if len(xRaw) > coordSize || len(yRaw) > coordSize {
		return nil, fmt.Errorf("sigalg: EC coordinate too large for %s", f.Crv)
	}

	// Validate the point with crypto/ecdh; NIST NewPublicKey accepts the
	// uncompressed encoding 0x04 || x || y and performs the on-curve check
	// previously done by the deprecated crypto/elliptic Curve.IsOnCurve.
	point := make([]byte, 1+2*coordSize)
	point[0] = 0x04
	copy(point[1+coordSize-len(xRaw):1+coordSize], xRaw)
	copy(point[1+2*coordSize-len(yRaw):1+2*coordSize], yRaw)

	if _, err := ecdhCurve.NewPublicKey(point); err != nil {
		return nil, errors.New("sigalg: EC public key is not on curve")
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xRaw),
		Y:     new(big.Int).SetBytes(yRaw),
	}

	return pub, nil
}

func publicKeyFromRSAFields(f JWKPublicKeyFields) (crypto.PublicKey, error) {
	nRaw, err := decodeBase64URL(f.N)
	if err != nil {
		return nil, fmt.Errorf("sigalg: decode RSA n: %w", err)
	}

	eRaw, err := decodeBase64URL(f.E)
	if err != nil {
		return nil, fmt.Errorf("sigalg: decode RSA e: %w", err)
	}

	if len(nRaw) == 0 || len(eRaw) == 0 {
		return nil, errors.New("sigalg: RSA JWK missing n or e")
	}

	eBI := new(big.Int).SetBytes(eRaw)
	if !eBI.IsInt64() {
		return nil, errors.New("sigalg: RSA exponent too large")
	}

	ei := eBI.Int64()
	if ei < 2 || ei > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("sigalg: invalid RSA exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nRaw),
		E: int(ei),
	}, nil
}

// PublicKeyFromJWK resolves an Ed25519 public key from a base64url-encoded x
// coordinate.
func PublicKeyFromJWK(kty, crv, x string) (crypto.PublicKey, error) {
	return PublicKeyFromJWKFields(JWKPublicKeyFields{Kty: kty, Crv: crv, X: x})
}

// SumSHA256 returns a SHA-256 digest helper for content-digest construction.
// OCM content-digest values must use a hash from the IANA "Hash Algorithms for
// HTTP Digest Fields" registry and implementations must support sha-256.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L856-L860
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L2025-L2026
func SumSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// SumSHA512 returns a SHA-512 digest helper for content-digest construction.
func SumSHA512(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}

// EncodeECDSARawRS encodes ECDSA r||s for RFC 9421 wire form.
func EncodeECDSARawRS(r, s *big.Int, coordSize int) ([]byte, error) {
	if r == nil || s == nil || coordSize <= 0 {
		return nil, errors.New("sigalg: invalid ecdsa raw encoding inputs")
	}

	out := make([]byte, coordSize*2)
	rBytes := r.Bytes()

	sBytes := s.Bytes()
	if len(rBytes) > coordSize || len(sBytes) > coordSize {
		return nil, errors.New("sigalg: ecdsa coordinate overflows fixed size")
	}

	copy(out[coordSize-len(rBytes):coordSize], rBytes)
	copy(out[2*coordSize-len(sBytes):], sBytes)

	return out, nil
}
