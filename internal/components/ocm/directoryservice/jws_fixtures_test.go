package directoryservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ed25519"
)

var testListing = Listing{
	Federation: "test-federation",
	Servers: []Server{
		{URL: "https://server1.example.com", DisplayName: "Server 1"},
		{URL: "https://server2.example.com", DisplayName: "Server 2"},
	},
}

func testPayload() []byte {
	b, err := json.Marshal(testListing) //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
	if err != nil {
		panic(err)
	}

	return b
}

func serveJWS(t *testing.T, body []byte) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test mock handler: response write
	}))
}

type ed25519KeyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	pem  string
}

type rsaKeyPair struct {
	pub  *rsa.PublicKey
	priv *rsa.PrivateKey
	pem  string
}

type ecdsaKeyPair struct {
	pub  *ecdsa.PublicKey
	priv *ecdsa.PrivateKey
	pem  string
}

func generateEd25519(t *testing.T) ed25519KeyPair {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	return ed25519KeyPair{pub: pub, priv: priv, pem: marshalPublicKeyPEM(t, pub)}
}

func generateRSA(t *testing.T) rsaKeyPair {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	return rsaKeyPair{pub: &priv.PublicKey, priv: priv, pem: marshalPublicKeyPEM(t, &priv.PublicKey)}
}

func generateECDSA(t *testing.T) ecdsaKeyPair {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}

	return ecdsaKeyPair{pub: &priv.PublicKey, priv: priv, pem: marshalPublicKeyPEM(t, &priv.PublicKey)}
}

func marshalPublicKeyPEM(t *testing.T, pub any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}

	return string(pem.EncodeToMemory(block))
}

func signCompact(t *testing.T, alg jose.SignatureAlgorithm, key any, payload []byte) []byte {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
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

func signFullSerialize(t *testing.T, alg jose.SignatureAlgorithm, key any, payload []byte) []byte {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	return []byte(jws.FullSerialize())
}

func assertListing(t *testing.T, listing *Listing) {
	t.Helper()

	if listing == nil {
		t.Fatal("listing is nil")
	}

	if listing.Federation != testListing.Federation {
		t.Errorf("federation = %q, want %q", listing.Federation, testListing.Federation)
	}

	if len(listing.Servers) != len(testListing.Servers) {
		t.Fatalf("server count = %d, want %d", len(listing.Servers), len(testListing.Servers))
	}

	for i, s := range listing.Servers {
		if s.URL != testListing.Servers[i].URL {
			t.Errorf("server[%d].URL = %q, want %q", i, s.URL, testListing.Servers[i].URL)
		}

		if s.DisplayName != testListing.Servers[i].DisplayName {
			t.Errorf("server[%d].DisplayName = %q, want %q", i, s.DisplayName, testListing.Servers[i].DisplayName)
		}
	}
}
