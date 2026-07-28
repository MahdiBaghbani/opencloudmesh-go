// Package directoryservice provides test helpers for Directory Service JWS fixtures.
package directoryservice

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ed25519"

	ds "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
)

// Ed25519Fixture holds a signing key pair and PEM for Directory Service JWS tests.
type Ed25519Fixture struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	PublicPEM  string
}

// GenerateEd25519Fixture creates an Ed25519 key pair for JWS signing tests.
func GenerateEd25519Fixture(t *testing.T) Ed25519Fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	return Ed25519Fixture{PublicKey: pub, PrivateKey: priv, PublicPEM: pemStr}
}

// VerificationKey returns the directoryservice.VerificationKey for this fixture.
func (f Ed25519Fixture) VerificationKey() ds.VerificationKey {
	return ds.VerificationKey{
		KeyID:        "test-key",
		PublicKeyPEM: f.PublicPEM,
		Algorithm:    "Ed25519",
		Active:       true,
	}
}

// SignListingCompact returns a compact-serialized JWS for the given listing payload.
func (f Ed25519Fixture) SignListingCompact(t *testing.T, listing ds.Listing) []byte {
	t.Helper()

	payload, err := json.Marshal(listing)
	if err != nil {
		t.Fatalf("marshal listing: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: f.PrivateKey}, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serialize: %v", err)
	}

	return []byte(compact)
}

// StartHTTPSDirectoryService serves signed JWS listing bodies over HTTPS.
func StartHTTPSDirectoryService(t *testing.T, body []byte) *httptest.Server {
	t.Helper()

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // response already started; write error cannot be recovered
		w.Write(body)
	}))
}
