package wellknown_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestJWKSHandler_ServesLocalKeys(t *testing.T) {
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	svc, err := wellknown.New(wellknown.Inputs{KeyManager: km}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, wellknown.RouteWellKnownJWKS, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

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
