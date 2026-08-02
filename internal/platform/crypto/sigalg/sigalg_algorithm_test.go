// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigalg_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	tscrypto "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/crypto"
)

func TestValidateAllowed_RejectsHMAC(t *testing.T) {
	err := sigalg.ValidateAllowed("hmac-sha256", sigalg.DefaultAllowed())
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("got %v, want ErrSymmetricNotPermitted", err)
	}
}

func TestValidateAllowed_AcceptsDefaultSet(t *testing.T) {
	for _, alg := range sigalg.DefaultAllowed() {
		if err := sigalg.ValidateAllowed(alg, sigalg.DefaultAllowed()); err != nil {
			t.Fatalf("unexpected error for %s: %v", alg, err)
		}
	}
}

func TestValidateAllowed_RejectsEmpty(t *testing.T) {
	if err := sigalg.ValidateAllowed("", sigalg.DefaultAllowed()); !errors.Is(err, sigalg.ErrMissingAlgorithm) {
		t.Fatalf("got %v, want ErrMissingAlgorithm", err)
	}
}

func TestNormalize_JOSENames(t *testing.T) {
	cases := map[string]string{
		"ed25519":           sigalg.Ed25519,
		"EdDSA":             sigalg.Ed25519,
		"eddsa":             sigalg.Ed25519,
		"ES256":             sigalg.ECDSAP256SHA256,
		"es256":             sigalg.ECDSAP256SHA256,
		"Es256":             sigalg.ECDSAP256SHA256,
		"ecdsa-p256-sha256": sigalg.ECDSAP256SHA256,
		"ES384":             sigalg.ECDSAP384SHA384,
		"RS256":             sigalg.RSAPKCS1SHA256,
		"rs256":             sigalg.RSAPKCS1SHA256,
		"RS384":             sigalg.RSAPKCS1SHA384,
		"RS512":             sigalg.RSAPKCS1SHA512,
	}
	for in, want := range cases {
		got, err := sigalg.Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}

		if got != want {
			t.Fatalf("Normalize(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestDeriveFromJWK(t *testing.T) {
	successes := []struct {
		name string
		kty  string
		crv  string
		alg  string
		want string
	}{
		{"OKP", "OKP", "Ed25519", "Ed25519", sigalg.Ed25519},
		{"EC P-256", "EC", "P-256", "ES256", sigalg.ECDSAP256SHA256},
		{"EC P-384", "EC", "P-384", "ES384", sigalg.ECDSAP384SHA384},
		{"RSA RS256", "RSA", "", "RS256", sigalg.RSAPKCS1SHA256},
	}

	for _, tt := range successes {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigalg.DeriveFromJWK(tt.kty, tt.crv, tt.alg)
			if err != nil || got != tt.want {
				t.Fatalf("got %q err %v, want %q", got, err, tt.want)
			}
		})
	}

	failures := []struct {
		name    string
		kty     string
		crv     string
		alg     string
		wantErr error
	}{
		{"OKP without alg", "OKP", "Ed25519", "", sigalg.ErrMissingAlgorithm},
		{"EC without alg", "EC", "P-256", "", sigalg.ErrMissingAlgorithm},
		{"RSA without alg", "RSA", "", "", sigalg.ErrMissingAlgorithm},
		{"OKP + ES256", "OKP", "Ed25519", "ES256", sigalg.ErrAlgorithmMismatch},
		{"EC P-256 + ES384", "EC", "P-256", "ES384", sigalg.ErrAlgorithmMismatch},
		{"EC P-384 + ES256", "EC", "P-384", "ES256", sigalg.ErrAlgorithmMismatch},
		{"EC + Ed25519", "EC", "P-256", "Ed25519", sigalg.ErrAlgorithmMismatch},
		{"RSA + ES256", "RSA", "", "ES256", sigalg.ErrAlgorithmMismatch},
	}

	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sigalg.DeriveFromJWK(tt.kty, tt.crv, tt.alg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveAlgorithm_HeaderOptionalAndAgreement(t *testing.T) {
	got, err := sigalg.ResolveAlgorithm("", "EC", "P-256", "ES256")
	if err != nil || got != sigalg.ECDSAP256SHA256 {
		t.Fatalf("omit header: got %q err %v", got, err)
	}

	got, err = sigalg.ResolveAlgorithm("ecdsa-p256-sha256", "EC", "P-256", "ES256")
	if err != nil || got != sigalg.ECDSAP256SHA256 {
		t.Fatalf("agree: got %q err %v", got, err)
	}

	_, err = sigalg.ResolveAlgorithm("ed25519", "EC", "P-256", "ES256")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("disagree: got %v", err)
	}

	got, err = sigalg.ResolveAlgorithm("rsa-v1_5-sha256", "RSA", "", "RS256")
	if err != nil || got != sigalg.RSAPKCS1SHA256 {
		t.Fatalf("RSA agree: got %q err %v", got, err)
	}

	_, err = sigalg.ResolveAlgorithm("rsa-v1_5-sha256", "RSA", "", "")
	if !errors.Is(err, sigalg.ErrMissingAlgorithm) {
		t.Fatalf("RSA from header without JWK alg: got %v, want ErrMissingAlgorithm", err)
	}

	_, err = sigalg.ResolveAlgorithm("ed25519", "RSA", "", "RS256")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("RSA header mismatch: got %v, want ErrAlgorithmMismatch", err)
	}

	// A valid native HTTP identifier naming a different algorithm than the
	// JWK-derived one must be rejected as a mismatch.
	_, err = sigalg.ResolveAlgorithm("ecdsa-p384-sha384", "EC", "P-256", "ES256")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("native header vs different JWK alg: got %v, want ErrAlgorithmMismatch", err)
	}
}

// TestResolveAlgorithm_RejectsJOSENamesInHeader asserts the Signature-Input
// alg parameter takes values from the IANA "HTTP Signature Algorithms"
// registry, not the JOSE registry: JOSE-only names are rejected even when
// they would denote the same algorithm as the JWK alg.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L903-L913
func TestResolveAlgorithm_RejectsJOSENamesInHeader(t *testing.T) {
	cases := []struct {
		name      string
		headerAlg string
		kty       string
		crv       string
		jwkAlg    string
	}{
		{"eddsa-vs-ed25519-jwk", "EdDSA", "OKP", "Ed25519", "Ed25519"},
		{"es256-vs-es256-jwk", "ES256", "EC", "P-256", "ES256"},
		{"es384-vs-es384-jwk", "ES384", "EC", "P-384", "ES384"},
		{"rs256-vs-rs256-jwk", "RS256", "RSA", "", "RS256"},
		{"rs256-lowercase", "rs256", "RSA", "", "RS256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sigalg.ResolveAlgorithm(tc.headerAlg, tc.kty, tc.crv, tc.jwkAlg)
			if err == nil {
				t.Fatalf("ResolveAlgorithm(%q, ...): expected JOSE name rejection", tc.headerAlg)
			}

			if errors.Is(err, sigalg.ErrAlgorithmMismatch) {
				t.Fatalf("ResolveAlgorithm(%q, ...): got %v, want unsupported-name rejection not mismatch", tc.headerAlg, err)
			}
		})
	}
}

func TestSignVerify_Ed25519(t *testing.T) {
	pub, priv := mustEd25519KeyPair(t)
	msg := []byte("signature base")

	sig, err := sigalg.Sign(sigalg.Ed25519, priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := sigalg.Verify(sigalg.Ed25519, pub, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_ECDSAP256_RawRS(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P256())
	msg := []byte("ocm signature base ecdsa-p256")
	digest := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sigalg.EncodeECDSARawRS(r, s, 32)
	if err != nil {
		t.Fatal(err)
	}

	if err := sigalg.Verify(sigalg.ECDSAP256SHA256, &priv.PublicKey, msg, raw); err != nil {
		t.Fatalf("Verify ES256: %v", err)
	}

	raw[0] ^= 0xff
	if err := sigalg.Verify(sigalg.ECDSAP256SHA256, &priv.PublicKey, msg, raw); !errors.Is(err, sigalg.ErrVerifyFailed) {
		t.Fatalf("tampered: got %v", err)
	}
}

func TestVerify_ECDSAP384_RawRS(t *testing.T) {
	priv := mustECDSAKey(t, elliptic.P384())
	msg := []byte("ocm signature base ecdsa-p384")
	sum := sha512.Sum384(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	raw, err := sigalg.EncodeECDSARawRS(r, s, 48)
	if err != nil {
		t.Fatal(err)
	}

	if err := sigalg.Verify(sigalg.ECDSAP384SHA384, &priv.PublicKey, msg, raw); err != nil {
		t.Fatalf("Verify ES384: %v", err)
	}
}

func TestVerify_RS256(t *testing.T) {
	priv := mustRSAKey(t)
	msg := []byte("ocm signature base rsa")
	digest := sha256.Sum256(msg)

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	if err := sigalg.Verify(sigalg.RSAPKCS1SHA256, &priv.PublicKey, msg, sig); err != nil {
		t.Fatalf("Verify RS256: %v", err)
	}
}

func TestVerify_RS384AndRS512(t *testing.T) {
	priv := mustRSAKey(t)
	msg := []byte("ocm signature base rsa-384-512")

	sum384 := sha512.Sum384(msg)

	sig384, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA384, sum384[:])
	if err != nil {
		t.Fatal(err)
	}

	if verr := sigalg.Verify(sigalg.RSAPKCS1SHA384, &priv.PublicKey, msg, sig384); verr != nil {
		t.Fatalf("Verify RS384: %v", verr)
	}

	sum512 := sha512.Sum512(msg)

	sig512, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, sum512[:])
	if err != nil {
		t.Fatal(err)
	}

	if err := sigalg.Verify(sigalg.RSAPKCS1SHA512, &priv.PublicKey, msg, sig512); err != nil {
		t.Fatalf("Verify RS512: %v", err)
	}
}

func TestPublicKeyFromJWK_Ed25519(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	x := base64.RawURLEncoding.EncodeToString(pub)

	got, err := sigalg.PublicKeyFromJWK("OKP", "Ed25519", x)
	if err != nil {
		t.Fatalf("PublicKeyFromJWK: %v", err)
	}

	gotPub, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("public key mismatch")
	}
}

func TestPublicKeyFromJWKFields_ECAndRSA(t *testing.T) {
	ecPriv := mustECDSAKey(t, elliptic.P256())
	x := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(tscrypto.PadCoord(ecPriv.Y.Bytes(), 32))

	got, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "EC", Crv: "P-256", Alg: "ES256", X: x, Y: y,
	})
	if err != nil {
		t.Fatalf("EC: %v", err)
	}

	ecPub, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ecPub type *ecdsa.PublicKey")
	}

	if !ecPub.Equal(&ecPriv.PublicKey) {
		t.Fatal("EC coordinate mismatch")
	}

	rsaPriv := mustRSAKey(t)
	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())

	got, err = sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "RSA", Alg: "RS256", N: n, E: e,
	})
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}

	rsaPub, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected RSA public key")
	}

	if rsaPub.N.Cmp(rsaPriv.N) != 0 {
		t.Fatal("RSA n mismatch")
	}
}

func TestVerify_RFC9421_B24_ECDSAP256(t *testing.T) {
	// Verify-only vector from RFC 9421 Appendix B.2.4 (ecdsa-p256-sha256).
	const signatureBase = "" +
		`"@status": 200` + "\n" +
		`"content-type": application/json` + "\n" +
		`"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:` + "\n" +
		`"content-length": 23` + "\n" +
		`"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`

	const signatureB64 = "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw=="

	raw, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "EC",
		Crv: "P-256",
		X:   "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA",
		Y:   "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sigalg.Verify(sigalg.ECDSAP256SHA256, pub, []byte(signatureBase), raw); err != nil {
		t.Fatalf("RFC 9421 B.2.4 ECDSA P-256 verify failed: %v", err)
	}
}

func TestNormalize_RejectsJOSESymmetric(t *testing.T) {
	for _, in := range []string{"HS256", "hs256", "HS384", "hs512"} {
		_, err := sigalg.Normalize(in)
		if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
			t.Fatalf("Normalize(%q) = %v, want ErrSymmetricNotPermitted", in, err)
		}
	}
}

// TestNormalizeSignatureInputAlgorithm_AcceptsNativeNames asserts the
// Signature-Input alg normalizer accepts every implemented RFC 9421 native
// name from the IANA "HTTP Signature Algorithms" registry, including ed25519,
// the one identifier that is also a valid JOSE name.
func TestNormalizeSignatureInputAlgorithm_AcceptsNativeNames(t *testing.T) {
	cases := map[string]string{
		"ed25519":           sigalg.Ed25519,
		"ED25519":           sigalg.Ed25519,
		"ecdsa-p256-sha256": sigalg.ECDSAP256SHA256,
		"ecdsa-p384-sha384": sigalg.ECDSAP384SHA384,
		"rsa-v1_5-sha256":   sigalg.RSAPKCS1SHA256,
		"rsa-v1_5-sha384":   sigalg.RSAPKCS1SHA384,
		"rsa-v1_5-sha512":   sigalg.RSAPKCS1SHA512,
	}
	for in, want := range cases {
		got, err := sigalg.NormalizeSignatureInputAlgorithm(in)
		if err != nil {
			t.Fatalf("NormalizeSignatureInputAlgorithm(%q): %v", in, err)
		}

		if got != want {
			t.Fatalf("NormalizeSignatureInputAlgorithm(%q)=%q, want %q", in, got, want)
		}
	}
}
