package sigalg_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestValidateAllowed_RejectsHMAC(t *testing.T) {
	err := sigalg.ValidateAllowed("hmac-sha256", sigalg.DefaultAllowed())
	if err == nil {
		t.Fatal("expected hmac-sha256 to be rejected")
	}
}

func TestValidateAllowed_AcceptsEd25519(t *testing.T) {
	if err := sigalg.ValidateAllowed("ed25519", sigalg.DefaultAllowed()); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
