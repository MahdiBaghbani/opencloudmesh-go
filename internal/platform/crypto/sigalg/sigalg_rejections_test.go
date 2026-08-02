// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigalg_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

// TestNormalizeSignatureInputAlgorithm_RejectsJOSENames asserts JOSE-registry
// names other than ed25519 are not valid Signature-Input alg values.
func TestNormalizeSignatureInputAlgorithm_RejectsJOSENames(t *testing.T) {
	for _, in := range []string{"EdDSA", "EDDSA", "eddsa", "ES256", "es256", "ES384", "RS256", "RS384", "RS512"} {
		_, err := sigalg.NormalizeSignatureInputAlgorithm(in)
		if err == nil {
			t.Fatalf("NormalizeSignatureInputAlgorithm(%q): expected JOSE name rejection", in)
		}

		if errors.Is(err, sigalg.ErrMissingAlgorithm) ||
			errors.Is(err, sigalg.ErrAlgorithmNotAllowed) ||
			errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
			t.Fatalf("NormalizeSignatureInputAlgorithm(%q) = %v, want unsupported-name error", in, err)
		}
	}
}

func TestNormalizeSignatureInputAlgorithm_ErrorClassification(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		for _, in := range []string{"none", "NONE", "None"} {
			_, err := sigalg.NormalizeSignatureInputAlgorithm(in)
			if !errors.Is(err, sigalg.ErrAlgorithmNotAllowed) {
				t.Fatalf("NormalizeSignatureInputAlgorithm(%q) = %v, want ErrAlgorithmNotAllowed", in, err)
			}
		}
	})

	t.Run("symmetric", func(t *testing.T) {
		for _, in := range []string{"HS256", "hs256", "hmac-sha256", "HS384", "hmac-sha512"} {
			_, err := sigalg.NormalizeSignatureInputAlgorithm(in)
			if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
				t.Fatalf("NormalizeSignatureInputAlgorithm(%q) = %v, want ErrSymmetricNotPermitted", in, err)
			}
		}
	})

	t.Run("missing", func(t *testing.T) {
		for _, in := range []string{"", "   "} {
			_, err := sigalg.NormalizeSignatureInputAlgorithm(in)
			if !errors.Is(err, sigalg.ErrMissingAlgorithm) {
				t.Fatalf("NormalizeSignatureInputAlgorithm(%q) = %v, want ErrMissingAlgorithm", in, err)
			}
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		for _, in := range []string{"rsa-pss-sha256", "rsa-pss-sha512", "ecdsa-p521-sha512", "unknown-alg"} {
			_, err := sigalg.NormalizeSignatureInputAlgorithm(in)
			if err == nil {
				t.Fatalf("NormalizeSignatureInputAlgorithm(%q): expected unsupported error", in)
			}

			if errors.Is(err, sigalg.ErrMissingAlgorithm) ||
				errors.Is(err, sigalg.ErrAlgorithmNotAllowed) ||
				errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
				t.Fatalf("NormalizeSignatureInputAlgorithm(%q) = %v, want unsupported error", in, err)
			}
		}
	})
}

func TestDeriveFromJWK_RejectsNoneAndSymmetric(t *testing.T) {
	_, err := sigalg.DeriveFromJWK("OKP", "Ed25519", "none")
	if !errors.Is(err, sigalg.ErrAlgorithmNotAllowed) {
		t.Fatalf("OKP none: got %v, want ErrAlgorithmNotAllowed", err)
	}

	_, err = sigalg.DeriveFromJWK("OKP", "Ed25519", "HS256")
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("OKP HS256: got %v, want ErrSymmetricNotPermitted", err)
	}

	_, err = sigalg.DeriveFromJWK("EC", "P-256", "HS256")
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("EC HS256: got %v, want ErrSymmetricNotPermitted", err)
	}

	_, err = sigalg.DeriveFromJWK("RSA", "", "HS256")
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("RSA HS256: got %v, want ErrSymmetricNotPermitted", err)
	}
}

// TestDeriveFromJWK_RejectsRFC9421NativeAlgNames asserts the JWK alg
// parameter MUST be a JOSE-registry name (RFC 7518). RFC 9421 native names
// such as ecdsa-p256-sha256 and rsa-v1_5-sha256 are not valid JWK alg values
// and must be rejected as unsupported JWK alg.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L879
func TestDeriveFromJWK_RejectsRFC9421NativeAlgNames(t *testing.T) {
	nativeNames := []struct {
		kty    string
		crv    string
		jwkAlg string
	}{
		{"OKP", "Ed25519", "ecdsa-p256-sha256"},
		{"EC", "P-256", "ecdsa-p256-sha256"},
		{"EC", "P-384", "ecdsa-p384-sha384"},
		{"RSA", "", "rsa-v1_5-sha256"},
		{"RSA", "", "rsa-v1_5-sha384"},
		{"RSA", "", "rsa-v1_5-sha512"},
		{"EC", "P-256", "RSA-V1_5-SHA256"},
		{"RSA", "", "ECDSA-P256-SHA256"},
	}
	for _, tc := range nativeNames {
		_, err := sigalg.DeriveFromJWK(tc.kty, tc.crv, tc.jwkAlg)
		if !errors.Is(err, sigalg.ErrUnsupportedJWKAlg) {
			t.Fatalf("DeriveFromJWK(%q,%q,%q): got %v, want ErrUnsupportedJWKAlg", tc.kty, tc.crv, tc.jwkAlg, err)
		}
	}
}

// TestDeriveFromJWK_AcceptsJOSENamesCaseInsensitive asserts the JWK alg
// parameter accepts JOSE-registry names case-insensitively for each kty/crv
// combination supported by the existing key-type compatibility logic.
func TestDeriveFromJWK_AcceptsJOSENamesCaseInsensitive(t *testing.T) {
	cases := []struct {
		name    string
		kty     string
		crv     string
		jwkAlg  string
		wantAlg string
	}{
		{"okp-ed25519-lower", "OKP", "Ed25519", "ed25519", sigalg.Ed25519},
		{"okp-ed25519-mixed", "OKP", "Ed25519", "Ed25519", sigalg.Ed25519},
		{"okp-eddsa-upper", "OKP", "Ed25519", "EDDSA", sigalg.Ed25519},
		{"okp-eddsa-mixed", "OKP", "Ed25519", "EdDsa", sigalg.Ed25519},
		{"ec-p256-es256-lower", "EC", "P-256", "es256", sigalg.ECDSAP256SHA256},
		{"ec-p256-es256-mixed", "EC", "P-256", "Es256", sigalg.ECDSAP256SHA256},
		{"ec-p384-es384-lower", "EC", "P-384", "es384", sigalg.ECDSAP384SHA384},
		{"ec-p384-es384-upper", "EC", "P-384", "ES384", sigalg.ECDSAP384SHA384},
		{"rsa-rs256-lower", "RSA", "", "rs256", sigalg.RSAPKCS1SHA256},
		{"rsa-rs256-mixed", "RSA", "", "Rs256", sigalg.RSAPKCS1SHA256},
		{"rsa-rs384-upper", "RSA", "", "RS384", sigalg.RSAPKCS1SHA384},
		{"rsa-rs512-upper", "RSA", "", "RS512", sigalg.RSAPKCS1SHA512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sigalg.DeriveFromJWK(tc.kty, tc.crv, tc.jwkAlg)
			if err != nil {
				t.Fatalf("DeriveFromJWK(%q,%q,%q): unexpected error %v", tc.kty, tc.crv, tc.jwkAlg, err)
			}

			if got != tc.wantAlg {
				t.Fatalf("DeriveFromJWK(%q,%q,%q)=%q, want %q", tc.kty, tc.crv, tc.jwkAlg, got, tc.wantAlg)
			}
		})
	}
}

func TestIsSymmetric_JOSENames(t *testing.T) {
	for _, in := range []string{"hmac-sha256", "HS256", "hs256", "hs384", "hs512"} {
		if !sigalg.IsSymmetric(in) {
			t.Fatalf("IsSymmetric(%q) = false", in)
		}
	}

	if sigalg.IsSymmetric("ed25519") || sigalg.IsSymmetric("") {
		t.Fatal("IsSymmetric should reject asymmetric/empty")
	}
}

func TestValidateAllowed_RejectsHS256(t *testing.T) {
	err := sigalg.ValidateAllowed("hs256", sigalg.DefaultAllowed())
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("got %v, want ErrSymmetricNotPermitted", err)
	}
}

func TestValidateAllowed_SkipsInvalidAllowListEntries(t *testing.T) {
	if err := sigalg.ValidateAllowed("ed25519", []string{"not-an-alg", "ed25519"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := sigalg.ValidateAllowed("ed25519", []string{"not-an-alg"})
	if !errors.Is(err, sigalg.ErrAlgorithmNotAllowed) {
		t.Fatalf("got %v, want ErrAlgorithmNotAllowed", err)
	}
}

func TestIsImplemented(t *testing.T) {
	if !sigalg.IsImplemented("ed25519") {
		t.Fatal("ed25519 should be implemented")
	}

	if sigalg.IsImplemented("ES256") || sigalg.IsImplemented("hs256") || sigalg.IsImplemented("") {
		t.Fatal("IsImplemented expects native lowercase identifiers only")
	}
}

func TestSign_NonEd25519NotImplemented(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())

	_, err := sigalg.Sign(sigalg.ECDSAP256SHA256, priv, []byte(testMsg))
	if !errors.Is(err, sigalg.ErrNotImplemented) {
		t.Fatalf("got %v, want ErrNotImplemented", err)
	}
}

func TestSign_WrongKeyType(t *testing.T) {
	priv := mustRSAKey(t)

	_, err := sigalg.Sign(sigalg.Ed25519, priv, []byte(testMsg))
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("got %v, want ErrWrongKeyType", err)
	}
}

func TestVerify_TypedNilAndWrongKeyType(t *testing.T) {
	sig := make([]byte, 64)

	err := sigalg.Verify(sigalg.ECDSAP256SHA256, (*ecdsa.PublicKey)(nil), []byte(testMsg), sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ecdsa: got %v, want ErrWrongKeyType", err)
	}

	err = sigalg.Verify(sigalg.RSAPKCS1SHA256, (*rsa.PublicKey)(nil), []byte(testMsg), sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil rsa: got %v, want ErrWrongKeyType", err)
	}

	err = sigalg.Verify(sigalg.Ed25519, ed25519.PublicKey(nil), []byte(testMsg), sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ed25519: got %v, want ErrWrongKeyType", err)
	}

	_, edPub := mustEd25519KeyPair(t)

	err = sigalg.Verify(sigalg.ECDSAP256SHA256, edPub, []byte(testMsg), sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("wrong type: got %v, want ErrWrongKeyType", err)
	}

	if errors.Is(err, sigalg.ErrVerifyFailed) {
		t.Fatal("wrong key type must not be ErrVerifyFailed")
	}
}

func TestSign_TypedNilEd25519(t *testing.T) {
	_, err := sigalg.Sign(sigalg.Ed25519, ed25519.PrivateKey(nil), []byte(testMsg))
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ed25519 private: got %v, want ErrWrongKeyType", err)
	}
}

func TestVerify_CurveMismatch(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())

	err := sigalg.Verify(sigalg.ECDSAP384SHA384, &priv.PublicKey, []byte(testMsg), make([]byte, 96))
	if !errors.Is(err, sigalg.ErrCurveMismatch) {
		t.Fatalf("got %v, want ErrCurveMismatch", err)
	}

	if errors.Is(err, sigalg.ErrVerifyFailed) {
		t.Fatal("curve mismatch must not be ErrVerifyFailed")
	}
}

func TestVerify_ECDSA_WrongLengthEncoding(t *testing.T) {
	cases := []struct {
		name      string
		alg       string
		curve     elliptic.Curve
		badLen    int
		coordSize int
	}{
		{name: "p256-empty", alg: sigalg.ECDSAP256SHA256, curve: elliptic.P256(), badLen: 0, coordSize: 32},
		{name: "p256-short", alg: sigalg.ECDSAP256SHA256, curve: elliptic.P256(), badLen: 63, coordSize: 32},
		{name: "p256-long", alg: sigalg.ECDSAP256SHA256, curve: elliptic.P256(), badLen: 65, coordSize: 32},
		{name: "p384-empty", alg: sigalg.ECDSAP384SHA384, curve: elliptic.P384(), badLen: 0, coordSize: 48},
		{name: "p384-short", alg: sigalg.ECDSAP384SHA384, curve: elliptic.P384(), badLen: 95, coordSize: 48},
		{name: "p384-long", alg: sigalg.ECDSAP384SHA384, curve: elliptic.P384(), badLen: 97, coordSize: 48},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv := mustECDSAKey(t, tc.curve)

			err := sigalg.Verify(tc.alg, &priv.PublicKey, []byte(testMsg), make([]byte, tc.badLen))
			if !errors.Is(err, sigalg.ErrInvalidSignatureEncoding) {
				t.Fatalf("got %v, want ErrInvalidSignatureEncoding", err)
			}

			if errors.Is(err, sigalg.ErrVerifyFailed) {
				t.Fatal("wrong-length encoding must not be ErrVerifyFailed")
			}
		})
	}
}

func TestEncodeECDSARawRS_Errors(t *testing.T) {
	r := big.NewInt(1)

	s := big.NewInt(1)
	if _, err := sigalg.EncodeECDSARawRS(nil, s, 32); err == nil {
		t.Fatal("nil r should error")
	}

	if _, err := sigalg.EncodeECDSARawRS(r, s, 0); err == nil {
		t.Fatal("coordSize<=0 should error")
	}

	tooBig := new(big.Int).Lsh(big.NewInt(1), 8*33)
	if _, err := sigalg.EncodeECDSARawRS(tooBig, s, 32); err == nil {
		t.Fatal("overflow should error")
	}
}

func TestPublicKeyFromJWKFields_Negative(t *testing.T) {
	if _, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "OKP", Crv: "Ed25519", X: "!!!",
	}); err == nil {
		t.Fatal("bad base64 should error")
	}

	if _, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
	}); err == nil {
		t.Fatal("short Ed25519 x should error")
	}

	if _, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Y: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}); err == nil {
		t.Fatal("off-curve EC should error")
	}

	if _, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString([]byte{1}),
		E:   base64.RawURLEncoding.EncodeToString([]byte{0}),
	}); err == nil {
		t.Fatal("e=0 should error")
	}

	oversized := make([]byte, 9)
	if _, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString([]byte{1}),
		E:   base64.RawURLEncoding.EncodeToString(oversized),
	}); err == nil {
		t.Fatal("oversized e should error")
	}
}
