// Package sigalg resolves and validates RFC 9421 HTTP signature algorithms.
package sigalg

import (
	"crypto"
	"crypto/ecdh"
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
)

// ResolvedPublicKey is key material plus the RFC 9421 native algorithm derived
// from the JWK alg parameter. Algorithm is always populated for supported
// JWKs; callers run ResolveAlgorithm to agree with an optional Signature-Input
// alg parameter.
type ResolvedPublicKey struct {
	KeyID     string
	Algorithm string
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
	case "EDDSA":
		return Ed25519, nil
	case "ES256":
		return ECDSAP256SHA256, nil
	case "ES384":
		return ECDSAP384SHA384, nil
	case "RS256":
		return RSAPKCS1SHA256, nil
	case "RS384":
		return RSAPKCS1SHA384, nil
	case "RS512":
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
	case "EDDSA", "ES256", "ES384", "RS256", "RS384", "RS512":
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
	case "ED25519", "EDDSA":
		return Ed25519, nil
	case "ES256":
		return ECDSAP256SHA256, nil
	case "ES384":
		return ECDSAP384SHA384, nil
	case "RS256":
		return RSAPKCS1SHA256, nil
	case "RS384":
		return RSAPKCS1SHA384, nil
	case "RS512":
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
