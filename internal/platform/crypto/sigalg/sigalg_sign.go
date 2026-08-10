// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package sigalg resolves and validates RFC 9421 HTTP signature algorithms.
package sigalg

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"strings"
)

const (
	// Ed25519 is the Ed25519 HTTP signature algorithm identifier.
	Ed25519 = "ed25519"
	// ECDSAP256SHA256 is the ECDSA P-256 SHA-256 signature algorithm identifier.
	ECDSAP256SHA256 = "ecdsa-p256-sha256"
	// ECDSAP384SHA384 is the ECDSA P-384 SHA-384 signature algorithm identifier.
	ECDSAP384SHA384 = "ecdsa-p384-sha384"
	// RSAPKCS1SHA256 is the RSA PKCS#1 SHA-256 signature algorithm identifier.
	RSAPKCS1SHA256 = "rsa-v1_5-sha256"
	// RSAPKCS1SHA384 is the RSA PKCS#1 SHA-384 signature algorithm identifier.
	RSAPKCS1SHA384 = "rsa-v1_5-sha384"
	// RSAPKCS1SHA512 is the RSA PKCS#1 SHA-512 signature algorithm identifier.
	RSAPKCS1SHA512 = "rsa-v1_5-sha512"
)

var (
	// ErrMissingAlgorithm reports a missing signature algorithm.
	ErrMissingAlgorithm = errors.New("sigalg: missing algorithm")
	// ErrAlgorithmMismatch reports disagreeing algorithm sources.
	ErrAlgorithmMismatch = errors.New("sigalg: algorithm sources disagree")
	// ErrAlgorithmNotAllowed reports a disallowed signature algorithm.
	ErrAlgorithmNotAllowed = errors.New("sigalg: algorithm is not allowed")
	// ErrVerifyFailed reports a failed signature verification.
	ErrVerifyFailed = errors.New("sigalg: signature verification failed")
	// ErrInvalidSignatureEncoding reports invalid signature encoding.
	ErrInvalidSignatureEncoding = errors.New("sigalg: invalid signature encoding")
	// ErrSymmetricNotPermitted reports a disallowed symmetric algorithm.
	ErrSymmetricNotPermitted = errors.New("sigalg: symmetric algorithm is not permitted")
	// ErrWrongKeyType reports a mismatched public key type.
	ErrWrongKeyType = errors.New("sigalg: wrong public key type")
	// ErrCurveMismatch reports an ECDSA curve mismatch.
	ErrCurveMismatch = errors.New("sigalg: ecdsa curve mismatch")
	// ErrNotImplemented reports an unimplemented signature algorithm.
	ErrNotImplemented = errors.New("sigalg: algorithm not implemented")
	// ErrUnsupportedJWKAlg reports a JWK alg that is not a JOSE-registry name.
	// RFC 9421 native names such as ecdsa-p256-sha256 are not valid JWK alg
	// values; the JWK alg MUST identify an algorithm in the IANA JSON Web
	// Signature and Encryption Algorithms registry (RFC 7518).
	ErrUnsupportedJWKAlg = errors.New("sigalg: unsupported JWK alg")
	// ErrWeakKey reports an RSA modulus below the configured local minimum.
	ErrWeakKey = errors.New("sigalg: weak key")
)

// MinRSAModulusBits is the default minimum RSA modulus size accepted during
// signature verification when callers do not supply an explicit floor.
const MinRSAModulusBits = 2048

// ResolvedPublicKey is key material plus the JWK algorithm inputs (kty, crv,
// alg) needed to derive the RFC 9421 native algorithm. Callers run
// ResolveAlgorithm to agree the JWK alg with an optional Signature-Input alg
// parameter.
type ResolvedPublicKey struct {
	KeyID     string
	PublicKey crypto.PublicKey
	JWKKty    string
	JWKCrv    string
	JWKAlg    string
}

// symmetricAlgorithms lists HMAC algorithms. OCM request signatures use an
// asymmetric algorithm identified by the JWK `alg` parameter from the IANA
// JOSE registry (RFC7518); Ed25519 is RECOMMENDED. The `none` algorithm and
// symmetric MAC algorithms such as HS256 MUST NOT be used.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L901
var symmetricAlgorithms = map[string]struct{}{
	"hmac-sha256": {},
	"hmac-sha384": {},
	"hmac-sha512": {},
	"hs256":       {},
	"hs384":       {},
	"hs512":       {},
}

var implemented = map[string]struct{}{
	Ed25519:         {},
	ECDSAP256SHA256: {},
	ECDSAP384SHA384: {},
	RSAPKCS1SHA256:  {},
	RSAPKCS1SHA384:  {},
	RSAPKCS1SHA512:  {},
}

// DefaultAllowed returns the default allowed asymmetric RFC 9421 algorithms.
func DefaultAllowed() []string {
	return []string{
		Ed25519,
		ECDSAP256SHA256,
		ECDSAP384SHA384,
		RSAPKCS1SHA256,
		RSAPKCS1SHA384,
		RSAPKCS1SHA512,
	}
}

// IsImplemented reports whether native alg has a verify implementation.
func IsImplemented(alg string) bool {
	_, ok := implemented[strings.ToLower(strings.TrimSpace(alg))]

	return ok
}

// IsSymmetric reports whether alg is a symmetric HMAC algorithm.
func IsSymmetric(alg string) bool {
	_, ok := symmetricAlgorithms[strings.ToLower(strings.TrimSpace(alg))]

	return ok
}

// Normalize maps JOSE or native algorithm identifiers to RFC 9421 native
// form. It serves non-header paths (signing, verification, and the configured
// allow-list) that historically accept JOSE aliases; the Signature-Input alg
// parameter must go through NormalizeSignatureInputAlgorithm instead.
func Normalize(alg string) (string, error) {
	trimmed := strings.TrimSpace(alg)
	if trimmed == "" {
		return "", ErrMissingAlgorithm
	}

	lower := strings.ToLower(trimmed)
	if _, ok := implemented[lower]; ok {
		return lower, nil
	}

	switch strings.ToUpper(trimmed) {
	case joseEdDSA:
		return Ed25519, nil
	case joseES256:
		return ECDSAP256SHA256, nil
	case joseES384:
		return ECDSAP384SHA384, nil
	case joseRS256:
		return RSAPKCS1SHA256, nil
	case joseRS384:
		return RSAPKCS1SHA384, nil
	case joseRS512:
		return RSAPKCS1SHA512, nil
	case "HS256", "HS384", "HS512":
		return "", fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, lower)
	default:
		if IsSymmetric(lower) {
			return "", fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, lower)
		}

		return "", fmt.Errorf("sigalg: unsupported signature algorithm %q", trimmed)
	}
}

// NormalizeSignatureInputAlgorithm maps the optional Signature-Input alg
// parameter to RFC 9421 native form, accepting only names from the IANA
// "HTTP Signature Algorithms" registry (RFC 9421 native names) that have a
// verify implementation. The Signature-Input alg takes values from a
// different registry than the JWK alg: JOSE-only names such as EdDSA, ES256,
// and RS256 are rejected here, while ed25519 is both a JOSE-registry name and
// the RFC 9421 native form, so it is accepted.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L903-L913
func NormalizeSignatureInputAlgorithm(alg string) (string, error) {
	trimmed := strings.TrimSpace(alg)
	if trimmed == "" {
		return "", ErrMissingAlgorithm
	}

	lower := strings.ToLower(trimmed)
	if _, ok := implemented[lower]; ok {
		return lower, nil
	}

	if strings.EqualFold(trimmed, "none") {
		return "", fmt.Errorf("%w: none", ErrAlgorithmNotAllowed)
	}

	if IsSymmetric(lower) {
		return "", fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, lower)
	}

	switch strings.ToUpper(trimmed) {
	case joseEdDSA, joseES256, joseES384, joseRS256, joseRS384, joseRS512:
		return "", fmt.Errorf("sigalg: JOSE name %q is not an HTTP Signature Algorithms registry name", trimmed)
	default:
		return "", fmt.Errorf("sigalg: unsupported Signature-Input algorithm %q", trimmed)
	}
}

// normalizeJWKAlg maps a JWK alg parameter to RFC 9421 native form, accepting
// only JOSE-registry names. The JWK alg MUST identify an asymmetric signature
// algorithm in the IANA "JSON Web Signature and Encryption Algorithms" registry
// (RFC 7518); RFC 9421 native names are not valid JWK alg values and are
// rejected as unsupported JWK alg. Ed25519 is the one identifier that is both
// a JOSE-registry name and the RFC 9421 native form, so it is accepted and is
// the recommended algorithm; all other RFC 9421 native names, such as
// ecdsa-p256-sha256 and rsa-v1_5-sha256, remain rejected.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L881
func normalizeJWKAlg(jwkAlg string) (string, error) {
	trimmed := strings.TrimSpace(jwkAlg)
	if trimmed == "" {
		return "", ErrMissingAlgorithm
	}

	switch strings.ToUpper(trimmed) {
	case "ED25519", joseEdDSA:
		return Ed25519, nil
	case joseES256:
		return ECDSAP256SHA256, nil
	case joseES384:
		return ECDSAP384SHA384, nil
	case joseRS256:
		return RSAPKCS1SHA256, nil
	case joseRS384:
		return RSAPKCS1SHA384, nil
	case joseRS512:
		return RSAPKCS1SHA512, nil
	case "HS256", "HS384", "HS512":
		return "", fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, strings.ToLower(trimmed))
	case "NONE":
		return "", fmt.Errorf("%w: none", ErrAlgorithmNotAllowed)
	default:
		lower := strings.ToLower(trimmed)
		if IsSymmetric(lower) {
			return "", fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, lower)
		}

		return "", fmt.Errorf("%w: %q", ErrUnsupportedJWKAlg, trimmed)
	}
}

// DeriveFromJWK derives a native RFC 9421 algorithm from JWK fields.
func DeriveFromJWK(kty, crv, jwkAlg string) (string, error) {
	kty = strings.ToUpper(strings.TrimSpace(kty))
	crv = strings.TrimSpace(crv)
	jwkAlg = strings.TrimSpace(jwkAlg)

	switch kty {
	case "OKP":
		return deriveFromJWKOKP(crv, jwkAlg)
	case "EC":
		return deriveFromJWKEC(crv, jwkAlg)
	case "RSA":
		return deriveFromJWKRSA(jwkAlg)
	default:
		return "", fmt.Errorf("sigalg: unsupported JWK kty %q", kty)
	}
}

func deriveFromJWKOKP(crv, jwkAlg string) (string, error) {
	if !strings.EqualFold(crv, "Ed25519") {
		return "", fmt.Errorf("sigalg: unsupported OKP curve %q", crv)
	}

	if strings.TrimSpace(jwkAlg) == "" {
		return "", fmt.Errorf("%w: OKP/Ed25519 JWK requires alg", ErrMissingAlgorithm)
	}

	native, err := normalizeJWKAlg(jwkAlg)
	if err != nil {
		return "", err
	}

	if native != Ed25519 {
		return "", fmt.Errorf("%w: JWK alg %q incompatible with OKP/Ed25519", ErrAlgorithmMismatch, jwkAlg)
	}

	return Ed25519, nil
}

func deriveFromJWKEC(crv, jwkAlg string) (string, error) {
	_, _, fromCrv, _, err := ecParamsFromCrv(crv) //nolint:dogsled // only the native algorithm name and error are needed from the 5-value curve classification
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(jwkAlg) == "" {
		return "", fmt.Errorf("%w: EC JWK requires alg", ErrMissingAlgorithm)
	}

	native, err := normalizeJWKAlg(jwkAlg)
	if err != nil {
		return "", err
	}

	if native != fromCrv {
		return "", fmt.Errorf("%w: JWK alg %q incompatible with EC/%s", ErrAlgorithmMismatch, jwkAlg, crv)
	}

	return fromCrv, nil
}

func deriveFromJWKRSA(jwkAlg string) (string, error) {
	if strings.TrimSpace(jwkAlg) == "" {
		return "", fmt.Errorf("%w: RSA JWK requires alg", ErrMissingAlgorithm)
	}

	native, err := normalizeJWKAlg(jwkAlg)
	if err != nil {
		return "", err
	}

	switch native {
	case RSAPKCS1SHA256, RSAPKCS1SHA384, RSAPKCS1SHA512:
		return native, nil
	default:
		return "", fmt.Errorf("%w: JWK alg %q incompatible with RSA", ErrAlgorithmMismatch, jwkAlg)
	}
}

// ecParamsFromCrv classifies an EC curve for DeriveFromJWK and
// PublicKeyFromJWKFields.
func ecParamsFromCrv(crv string) (elliptic.Curve, ecdh.Curve, string, int, error) {
	switch strings.ToUpper(strings.TrimSpace(crv)) {
	case "P-256":
		return elliptic.P256(), ecdh.P256(), ECDSAP256SHA256, 32, nil
	case "P-384":
		return elliptic.P384(), ecdh.P384(), ECDSAP384SHA384, 48, nil
	default:
		return nil, nil, "", 0, fmt.Errorf("sigalg: unsupported EC curve %q", crv)
	}
}

// ResolveAlgorithm applies RFC 9421 section 3.2: the algorithm is determined
// from the JWK identified by the keyid signature parameter. If the optional
// Signature-Input alg parameter is present, it must be an IANA "HTTP
// Signature Algorithms" registry name denoting the same algorithm; JOSE names
// valid in the JWK alg are not valid in the Signature-Input alg.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L914
func ResolveAlgorithm(headerAlg, kty, crv, jwkAlg string) (string, error) {
	derived, err := DeriveFromJWK(kty, crv, jwkAlg)
	if err != nil {
		return "", err
	}

	headerAlg = strings.TrimSpace(headerAlg)
	if headerAlg == "" {
		return derived, nil
	}

	headerNative, err := NormalizeSignatureInputAlgorithm(headerAlg)
	if err != nil {
		return "", err
	}

	if headerNative != derived {
		return "", fmt.Errorf("%w: Signature-Input alg %q vs JWK-derived alg %q", ErrAlgorithmMismatch, headerNative, derived)
	}

	return derived, nil
}

// ValidateAllowed rejects symmetric algorithms and algorithms outside the
// configured allow-list. alg must already be resolved (non-empty).
//
// Allow-list entries should already be normalized asymmetric algorithms
// (config.Load validates this). Unnormalizable entries are ignored.
func ValidateAllowed(alg string, allowed []string) error {
	alg = strings.ToLower(strings.TrimSpace(alg))
	if alg == "" {
		return ErrMissingAlgorithm
	}

	if IsSymmetric(alg) {
		return fmt.Errorf("%w: %s", ErrSymmetricNotPermitted, alg)
	}

	if !IsImplemented(alg) {
		return fmt.Errorf("%w: %s", ErrNotImplemented, alg)
	}

	for _, candidate := range allowed {
		normalized, err := Normalize(candidate)
		if err != nil {
			continue
		}

		if normalized == alg {
			return nil
		}
	}

	return fmt.Errorf("%w: %s", ErrAlgorithmNotAllowed, alg)
}

// Sign signs message with the given algorithm and private key material.
func Sign(alg string, privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
	native, err := Normalize(alg)
	if err != nil {
		return nil, err
	}

	switch native {
	case Ed25519:
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok || key == nil {
			return nil, fmt.Errorf("%w: expected ed25519.PrivateKey", ErrWrongKeyType)
		}

		return ed25519.Sign(key, message), nil
	default:
		return nil, fmt.Errorf("%w: signing for %q", ErrNotImplemented, native)
	}
}
