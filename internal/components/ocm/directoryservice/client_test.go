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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
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
	b, _ := json.Marshal(testListing)
	return b
}

func newTestHTTPClient() *httpclient.Client {
	return httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     0,
		MaxResponseBytes: 1048576,
	}, nil)
}

func serveJWS(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
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

func TestFetchListing_CompactJWS_Ed25519(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_CompactJWS_RS256(t *testing.T) {
	kp := generateRSA(t)
	body := signCompact(t, jose.RS256, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "RS256", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_CompactJWS_ES256(t *testing.T) {
	kp := generateECDSA(t)
	body := signCompact(t, jose.ES256, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "ES256", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_FlattenedJSON_Ed25519(t *testing.T) {
	kp := generateEd25519(t)
	body := signFullSerialize(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_GeneralJSON_MultipleSignatures(t *testing.T) {
	kp1 := generateEd25519(t)
	kp2 := generateRSA(t)

	ms, err := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.EdDSA, Key: kp1.priv},
		{Algorithm: jose.RS256, Key: kp2.priv},
	}, nil)
	if err != nil {
		t.Fatalf("create multi-signer: %v", err)
	}

	jws, err := ms.Sign(testPayload())
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	body := []byte(jws.FullSerialize())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{
		{KeyID: "k1", PublicKeyPEM: kp1.pem, Algorithm: "Ed25519", Active: true},
		{KeyID: "k2", PublicKeyPEM: kp2.pem, Algorithm: "RS256", Active: true},
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_InvalidSignature(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	bodyStr := string(body)
	bodyStr = bodyStr[:len(bodyStr)-4] + "XXXX"

	ts := serveJWS(t, []byte(bodyStr))
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected verification error, got nil")
	}
}

func TestFetchListing_WrongKey(t *testing.T) {
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected verification error for wrong key, got nil")
	}
}

func TestFetchListing_InactiveKey(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: false}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for inactive key, got nil")
	}
}

func TestFetchListing_MissingFederationField(t *testing.T) {
	kp := generateEd25519(t)
	payload, _ := json.Marshal(map[string]any{
		"servers": []map[string]string{{"url": "https://a.example.com", "displayName": "A"}},
	})
	body := signCompact(t, jose.EdDSA, kp.priv, payload)

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for missing federation field, got nil")
	}
}

func TestFetchListing_UnsignedPayload(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for unsigned payload, got nil")
	}
}

func TestFetchListing_NoActiveKeys(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for no active keys, got nil")
	}
}

func TestFetchListing_MultipleKeys_SecondMatches(t *testing.T) {
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{
		{KeyID: "wrong", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true},
		{KeyID: "correct", PublicKeyPEM: signing.pem, Algorithm: "Ed25519", Active: true},
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_AlgorithmCaseInsensitive(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertListing(t, listing)
}

func TestFetchListing_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestCollectAlgorithms(t *testing.T) {
	keys := []VerificationKey{
		{Algorithm: "Ed25519", Active: true},
		{Algorithm: "RS256", Active: true},
		{Algorithm: "ES256", Active: true},
		{Algorithm: "Ed25519", Active: true},
		{Algorithm: "RS256", Active: false},
		{Algorithm: "unknown", Active: true},
	}

	algs := collectAlgorithms(keys)
	if len(algs) != 3 {
		t.Fatalf("expected 3 algorithms, got %d: %v", len(algs), algs)
	}

	expected := map[jose.SignatureAlgorithm]bool{jose.EdDSA: true, jose.RS256: true, jose.ES256: true}
	for _, a := range algs {
		if !expected[a] {
			t.Errorf("unexpected algorithm: %v", a)
		}
	}
}

func TestMapAlgorithm(t *testing.T) {
	cases := []struct {
		input string
		want  jose.SignatureAlgorithm
		ok    bool
	}{
		{"Ed25519", jose.EdDSA, true},
		{"ed25519", jose.EdDSA, true},
		{"EdDSA", jose.EdDSA, true},
		{"RS256", jose.RS256, true},
		{"ES256", jose.ES256, true},
		{"unknown", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		got, ok := mapAlgorithm(tc.input)
		if ok != tc.ok || got != tc.want {
			t.Errorf("mapAlgorithm(%q) = (%v, %v), want (%v, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	kp := generateEd25519(t)
	pub, err := parsePublicKey(kp.pem)
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	_, err := parsePublicKey("not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestFetchListing_Required_SetsVerifiedTrue(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listing.Verified {
		t.Error("expected Verified=true for required policy with valid JWS")
	}
}

func TestFetchListing_Optional_UnsignedPayload_Accepted(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listing.Verified {
		t.Error("expected Verified=false for unsigned payload with optional policy")
	}
	assertListing(t, listing)
}

func TestFetchListing_Optional_ValidJWS_Verified(t *testing.T) {
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listing.Verified {
		t.Error("expected Verified=true for valid JWS with optional policy")
	}
	assertListing(t, listing)
}

func TestFetchListing_Optional_BadSignature_Rejected(t *testing.T) {
	signing := generateEd25519(t)
	wrong := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, signing.priv, testPayload())

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: wrong.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for bad signature with optional policy")
	}
}

func TestFetchListing_Optional_NoKeys_AcceptsAsUnsigned(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	keys := []VerificationKey{}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listing.Verified {
		t.Error("expected Verified=false with no keys in optional mode")
	}
	assertListing(t, listing)
}

func TestFetchListing_Off_Accepted(t *testing.T) {
	ts := serveJWS(t, testPayload())
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "off", nil)
	keys := []VerificationKey{}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listing.Verified {
		t.Error("expected Verified=false for off policy")
	}
	assertListing(t, listing)
}

func TestFetchListing_PerCallPolicyOverridesDefault(t *testing.T) {
	ts := serveJWS(t, testPayload()) // unsigned payload
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	_, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err == nil {
		t.Fatal("expected error for unsigned payload with required default policy")
	}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "off")
	if err != nil {
		t.Fatalf("unexpected error with per-call off policy: %v", err)
	}
	if listing.Verified {
		t.Error("expected Verified=false for off policy")
	}
}

func TestFetchListing_URLValidation_VerifiedListingFiltersInvalidURLs(t *testing.T) {
	payload, _ := json.Marshal(Listing{
		Federation: "test-federation",
		Servers: []Server{
			{URL: "https://valid.example.com", DisplayName: "Valid"},
			{URL: "https://also-valid.example.com:9200", DisplayName: "Also Valid"},
			{URL: "https://also-valid.example.com/", DisplayName: "Also Valid Trailing Slash"},
			{URL: "https://has-path.example.com/base/path", DisplayName: "Has Path"},
			{URL: "https://user:pass@has-userinfo.example.com", DisplayName: "Has Userinfo"},
			{URL: "https://has-query.example.com?q=1", DisplayName: "Has Query"},
			{URL: "ftp://wrong-scheme.example.com", DisplayName: "Wrong Scheme"},
		},
	})
	kp := generateEd25519(t)
	body := signCompact(t, jose.EdDSA, kp.priv, payload)

	ts := serveJWS(t, body)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "required", nil)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listing.Verified {
		t.Error("expected Verified=true")
	}
	if len(listing.Servers) != 3 {
		t.Fatalf("expected 3 valid servers after filtering, got %d: %v", len(listing.Servers), listing.Servers)
	}
	expectedURLs := map[string]bool{
		"https://valid.example.com":           true,
		"https://also-valid.example.com:9200": true,
		"https://also-valid.example.com/":     true,
	}
	for _, s := range listing.Servers {
		if !expectedURLs[s.URL] {
			t.Errorf("unexpected server URL after filtering: %q", s.URL)
		}
	}
}

func TestFetchListing_URLValidation_UnverifiedListingKeepsAllURLs(t *testing.T) {
	payload, _ := json.Marshal(Listing{
		Federation: "test-federation",
		Servers: []Server{
			{URL: "https://valid.example.com", DisplayName: "Valid"},
			{URL: "https://has-path.example.com/base/path", DisplayName: "Has Path"},
		},
	})
	ts := serveJWS(t, payload)
	defer ts.Close()

	client := NewClient(newTestHTTPClient(), "optional", nil)
	kp := generateEd25519(t)
	keys := []VerificationKey{{KeyID: "k1", PublicKeyPEM: kp.pem, Algorithm: "Ed25519", Active: true}}

	listing, err := client.FetchListing(t.Context(), ts.URL, keys, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listing.Verified {
		t.Error("expected Verified=false for unsigned payload")
	}
	if len(listing.Servers) != 2 {
		t.Errorf("expected 2 servers (no filtering for unverified), got %d", len(listing.Servers))
	}
}

func TestIsValidServerURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com", true},
		{"https://example.com/", true},
		{"https://example.com:9200", true},
		{"http://example.com", true},
		{"https://example.com/base/path", false},
		{"https://user:pass@example.com", false},
		{"https://example.com?q=1", false},
		{"https://example.com#frag", false},
		{"ftp://example.com", false},
		{"not-a-url", false},
		{"", false},
		{"/relative/path", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got := isValidServerURL(tc.url)
			if got != tc.want {
				t.Errorf("isValidServerURL(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
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
