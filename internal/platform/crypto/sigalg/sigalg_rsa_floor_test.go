// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigalg_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func rsaJWKFromPriv(priv *rsa.PrivateKey) sigalg.JWKPublicKeyFields {
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())

	return sigalg.JWKPublicKeyFields{
		Kty: "RSA",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}

func signRS256(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign RS256: %w", err)
	}

	return sig, nil
}

func verifyRSAJWK(t *testing.T, fields sigalg.JWKPublicKeyFields, msg, signature []byte, minModulusBits int) error {
	t.Helper()

	pub, err := sigalg.PublicKeyFromJWKFields(fields)
	if err != nil {
		t.Fatalf("PublicKeyFromJWKFields: %v", err)
	}

	opts := sigalg.VerifyOptions{MinRSAModulusBits: minModulusBits}
	if err := sigalg.VerifyWithOptions(sigalg.RSAPKCS1SHA256, pub, msg, signature, opts); err != nil {
		return fmt.Errorf("verify RSA JWK: %w", err)
	}

	return nil
}

func TestVerifyJWK_RejectsRSABelow2048(t *testing.T) {
	t.Parallel()

	msg := []byte("ocm rsa modulus floor")

	weakPriv := mustRSAKeyBits(t, 1024)

	weakSig, err := signRS256(weakPriv, msg)
	if err != nil {
		t.Fatal(err)
	}

	err = verifyRSAJWK(t, rsaJWKFromPriv(weakPriv), msg, weakSig, 2048)
	if !errors.Is(err, sigalg.ErrWeakKey) {
		t.Fatalf("1024-bit RSA: got %v, want ErrWeakKey", err)
	}

	strongPriv := mustRSAKey(t)

	strongSig, err := signRS256(strongPriv, msg)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyRSAJWK(t, rsaJWKFromPriv(strongPriv), msg, strongSig, 2048); err != nil {
		t.Fatalf("2048-bit RSA: %v", err)
	}
}

func TestVerifyRSA_ModulusFloorConfigurable(t *testing.T) {
	t.Parallel()

	priv := mustRSAKeyBits(t, 1024)
	msg := []byte("configurable rsa floor")
	fields := rsaJWKFromPriv(priv)

	sig, err := signRS256(priv, msg)
	if err != nil {
		t.Fatal(err)
	}

	if verr := verifyRSAJWK(t, fields, msg, sig, 1024); verr != nil {
		t.Fatalf("floor 1024: %v", verr)
	}

	err = verifyRSAJWK(t, fields, msg, sig, 2048)
	if !errors.Is(err, sigalg.ErrWeakKey) {
		t.Fatalf("floor 2048: got %v, want ErrWeakKey", err)
	}
}

func FuzzVerify_RSAJWK(f *testing.F) {
	const floor = 2048

	type rsaKeyCase struct {
		bits int
		priv *rsa.PrivateKey
	}

	cases := []rsaKeyCase{
		{bits: 1024},
		{bits: 2048},
		{bits: 3072},
	}

	for i := range cases {
		priv, err := rsa.GenerateKey(rand.Reader, cases[i].bits)
		if err != nil {
			f.Fatalf("generate %d-bit RSA key: %v", cases[i].bits, err)
		}

		cases[i].priv = priv
	}

	seedMsg0 := []byte("seed")
	seedMsg1 := []byte("ocm fuzz rsa jwk")

	seedSig0, err := signRS256(cases[0].priv, seedMsg0)
	if err != nil {
		f.Fatalf("seed sign weak key: %v", err)
	}

	seedSig2, err := signRS256(cases[2].priv, seedMsg1)
	if err != nil {
		f.Fatalf("seed sign strong key: %v", err)
	}

	tamperedSig2 := append([]byte(nil), seedSig2...)
	tamperedSig2[0] ^= 0xff

	f.Add(byte(0), seedMsg0, seedSig0)
	f.Add(byte(2), seedMsg1, seedSig2)
	f.Add(byte(2), seedMsg1, tamperedSig2)

	f.Fuzz(func(t *testing.T, keySel byte, msg, sig []byte) {
		if len(msg) == 0 {
			msg = []byte("fuzz")
		}

		idx := int(keySel) % len(cases)
		kc := cases[idx]

		validSig, err := signRS256(kc.priv, msg)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		if len(sig) == 0 {
			sig = validSig
		}

		err = verifyRSAJWK(t, rsaJWKFromPriv(kc.priv), msg, sig, floor)
		if kc.priv.N.BitLen() < floor {
			if !errors.Is(err, sigalg.ErrWeakKey) {
				t.Fatalf("%d-bit key: got %v, want ErrWeakKey", kc.priv.N.BitLen(), err)
			}

			return
		}

		if bytes.Equal(sig, validSig) {
			if err != nil {
				t.Fatalf("%d-bit key valid sig: %v", kc.priv.N.BitLen(), err)
			}

			return
		}

		if err == nil {
			t.Fatalf("%d-bit key tampered sig: got nil, want ErrVerifyFailed", kc.priv.N.BitLen())
		}

		if errors.Is(err, sigalg.ErrWeakKey) {
			t.Fatalf("%d-bit key tampered sig: got ErrWeakKey, want ErrVerifyFailed", kc.priv.N.BitLen())
		}

		if !errors.Is(err, sigalg.ErrVerifyFailed) {
			t.Fatalf("%d-bit key tampered sig: got %v, want ErrVerifyFailed", kc.priv.N.BitLen(), err)
		}
	})
}
