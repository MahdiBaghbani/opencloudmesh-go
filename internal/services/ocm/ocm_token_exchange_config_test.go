package ocm

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func TestNew_EvaluatorOwnsTokenExchangeEnablement(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		TokenExchange: config.TokenExchangeConfig{
			Path: "token",
		},
	}
	in := testInputs(cfg)

	m := map[string]any{
		"token_exchange": map[string]any{
			"enabled": false,
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(in, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected token route to stay mounted (405 on GET), got %d", w.Code)
	}
}

func TestNew_RawConfigDoesNotBackfillTokenExchangeEnablement(t *testing.T) {
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		TokenExchange: config.TokenExchangeConfig{
			Path: "token",
		},
	}
	id := tslocalid.MustTestIdentity(t, cfg.PublicOrigin, cfg.ExternalBasePath)

	// The token route requires a verified signature; sign with a key bound
	// to the client_id host so the request reaches the handler and exercises
	// the enablement check under test, not the signature gate.
	const clientHost = "raw-config-client.example.com"

	signer, pd := hostSigningFixture(t, clientHost)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	in := Inputs{
		LocalIdentity:     id,
		PartyRepo:         identity.NewMemoryPartyRepo(),
		TokenExchangePath: "token",
	}
	replaceSignatureMiddleware(&in, cfg, pd)

	svc, err := New(in, map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	form := "grant_type=authorization_code&client_id=" + clientHost + "&code=raw-config-code"
	body := []byte(form)
	req := httptest.NewRequest(http.MethodPost, cfg.PublicOrigin+"/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("sign request: %v", err)
	}

	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected disabled token exchange without canonical policy, got %d: %s", w.Code, w.Body.String())
	}
}
