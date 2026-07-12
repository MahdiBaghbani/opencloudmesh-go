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

func TestNormalize_JOSEAliases(t *testing.T) {
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
	got, err := sigalg.DeriveFromJWK("OKP", "Ed25519", "")
	if err != nil || got != sigalg.Ed25519 {
		t.Fatalf("OKP: got %q err %v", got, err)
	}
	got, err = sigalg.DeriveFromJWK("EC", "P-256", "ES256")
	if err != nil || got != sigalg.ECDSAP256SHA256 {
		t.Fatalf("EC P-256: got %q err %v", got, err)
	}
	got, err = sigalg.DeriveFromJWK("EC", "P-384", "")
	if err != nil || got != sigalg.ECDSAP384SHA384 {
		t.Fatalf("EC P-384: got %q err %v", got, err)
	}
	_, err = sigalg.DeriveFromJWK("RSA", "", "")
	if !errors.Is(err, sigalg.ErrAlgorithmUnderdetermined) {
		t.Fatalf("RSA without alg: got %v", err)
	}
	got, err = sigalg.DeriveFromJWK("RSA", "", "RS256")
	if err != nil || got != sigalg.RSAPKCS1SHA256 {
		t.Fatalf("RSA RS256: got %q err %v", got, err)
	}
	_, err = sigalg.DeriveFromJWK("OKP", "Ed25519", "ES256")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("OKP + ES256: got %v, want ErrAlgorithmMismatch", err)
	}
	_, err = sigalg.DeriveFromJWK("EC", "P-256", "ES384")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("EC P-256 + ES384: got %v, want ErrAlgorithmMismatch", err)
	}
	_, err = sigalg.DeriveFromJWK("EC", "P-384", "ES256")
	if !errors.Is(err, sigalg.ErrAlgorithmMismatch) {
		t.Fatalf("EC P-384 + ES256: got %v, want ErrAlgorithmMismatch", err)
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
	got, err = sigalg.ResolveAlgorithm("RS256", "RSA", "", "")
	if err != nil || got != sigalg.RSAPKCS1SHA256 {
		t.Fatalf("RSA from header: got %q err %v", got, err)
	}
	_, err = sigalg.ResolveAlgorithm("", "RSA", "", "")
	if !errors.Is(err, sigalg.ErrAlgorithmUnderdetermined) {
		t.Fatalf("RSA omit both: got %v", err)
	}
	_, err = sigalg.ResolveAlgorithm("ed25519", "RSA", "", "")
	if !errors.Is(err, sigalg.ErrAlgorithmUnderdetermined) {
		t.Fatalf("RSA bad header: got %v", err)
	}
}

func TestSignVerify_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("ocm signature base rsa-384-512")

	sum384 := sha512.Sum384(msg)
	sig384, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA384, sum384[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sigalg.Verify(sigalg.RSAPKCS1SHA384, &priv.PublicKey, msg, sig384); err != nil {
		t.Fatalf("Verify RS384: %v", err)
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
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	got, err := sigalg.PublicKeyFromJWK("OKP", "Ed25519", x)
	if err != nil {
		t.Fatalf("PublicKeyFromJWK: %v", err)
	}
	if !pub.Equal(got.(ed25519.PublicKey)) {
		t.Fatal("public key mismatch")
	}
}

func TestPublicKeyFromJWKFields_ECAndRSA(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(padCoord(ecPriv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoord(ecPriv.Y.Bytes(), 32))
	got, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "EC", Crv: "P-256", Alg: "ES256", X: x, Y: y,
	})
	if err != nil {
		t.Fatalf("EC: %v", err)
	}
	ecPub := got.(*ecdsa.PublicKey)
	if ecPub.X.Cmp(ecPriv.X) != 0 || ecPub.Y.Cmp(ecPriv.Y) != 0 {
		t.Fatal("EC coordinate mismatch")
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())
	got, err = sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: "RSA", Alg: "RS256", N: n, E: e,
	})
	if err != nil {
		t.Fatalf("RSA: %v", err)
	}
	if got.(*rsa.PublicKey).N.Cmp(rsaPriv.N) != 0 {
		t.Fatal("RSA n mismatch")
	}
}

func padCoord(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// Verify-only vector from RFC 9421 Appendix B.2.4 (ecdsa-p256-sha256).
func TestVerify_RFC9421_B24_ECDSAP256(t *testing.T) {
	const signatureBase = "" +
		`"@status": 200` + "\n" +
		`"content-type": application/json` + "\n" +
		`"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:` + "\n" +
		`"content-length": 23` + "\n" +
		`"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`

	sigB64 := "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw=="
	raw, err := base64.StdEncoding.DecodeString(sigB64)
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

func TestIsSymmetric_JOSEAliases(t *testing.T) {
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigalg.Sign(sigalg.ECDSAP256SHA256, priv, []byte("msg"))
	if !errors.Is(err, sigalg.ErrNotImplemented) {
		t.Fatalf("got %v, want ErrNotImplemented", err)
	}
}

func TestSign_WrongKeyType(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigalg.Sign(sigalg.Ed25519, priv, []byte("msg"))
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("got %v, want ErrWrongKeyType", err)
	}
}

func TestVerify_TypedNilAndWrongKeyType(t *testing.T) {
	msg := []byte("msg")
	sig := make([]byte, 64)
	err := sigalg.Verify(sigalg.ECDSAP256SHA256, (*ecdsa.PublicKey)(nil), msg, sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ecdsa: got %v, want ErrWrongKeyType", err)
	}
	err = sigalg.Verify(sigalg.RSAPKCS1SHA256, (*rsa.PublicKey)(nil), msg, sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil rsa: got %v, want ErrWrongKeyType", err)
	}
	err = sigalg.Verify(sigalg.Ed25519, ed25519.PublicKey(nil), msg, sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ed25519: got %v, want ErrWrongKeyType", err)
	}
	_, edPub, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = sigalg.Verify(sigalg.ECDSAP256SHA256, edPub, msg, sig)
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("wrong type: got %v, want ErrWrongKeyType", err)
	}
	if errors.Is(err, sigalg.ErrVerifyFailed) {
		t.Fatal("wrong key type must not be ErrVerifyFailed")
	}
}

func TestSign_TypedNilEd25519(t *testing.T) {
	_, err := sigalg.Sign(sigalg.Ed25519, ed25519.PrivateKey(nil), []byte("msg"))
	if !errors.Is(err, sigalg.ErrWrongKeyType) {
		t.Fatalf("typed-nil ed25519 private: got %v, want ErrWrongKeyType", err)
	}
}

func TestVerify_CurveMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = sigalg.Verify(sigalg.ECDSAP384SHA384, &priv.PublicKey, []byte("msg"), make([]byte, 96))
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
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			err = sigalg.Verify(tc.alg, &priv.PublicKey, []byte("msg"), make([]byte, tc.badLen))
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

