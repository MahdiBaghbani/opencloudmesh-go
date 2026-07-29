package ocm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestJWKSHandler_ServesLocalKeys(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, RouteJWKS, nil)
	rec := httptest.NewRecorder()
	newJWKSHandler(km).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var set jwks.Set
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d", len(set.Keys))
	}

	if set.Keys[0].Kid != km.GetKeyID() {
		t.Fatalf("kid = %q, want %q", set.Keys[0].Kid, km.GetKeyID())
	}
}

func TestJWKSHandler_NilKeyManagerServesUnavailable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, RouteJWKS, nil)
	rec := httptest.NewRecorder()
	newJWKSHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestService_MountsJWKSRoute proves the OCM service mounts GET /jwks
// publicly and unauthenticated, serving the JWK set without going through
// the POST HTTPSig/peer-resolution middleware chain.
func TestService_MountsJWKSRoute(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	in := setupTestInputs()
	in.KeyManager = km

	svc, err := New(in, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, RouteJWKS, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var set jwks.Set
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(set.Keys) != 1 || set.Keys[0].Kid != km.GetKeyID() {
		t.Fatalf("unexpected JWKS body: %+v", set)
	}
}
