package tls

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestHTTP01Provider_PresentAndCleanUp(t *testing.T) {
	p := &HTTP01Provider{}

	if err := p.Present("example.com", "tok1", "keyAuth1"); err != nil {
		t.Fatalf("Present(tok1): %v", err)
	}
	if err := p.Present("example.com", "tok2", "keyAuth2"); err != nil {
		t.Fatalf("Present(tok2): %v", err)
	}

	if v, ok := p.tokens.Load("tok1"); !ok || v.(tokenEntry).keyAuth != "keyAuth1" {
		t.Errorf("tok1: got %v, ok=%v; want keyAuth1, true", v, ok)
	}
	if v, ok := p.tokens.Load("tok2"); !ok || v.(tokenEntry).keyAuth != "keyAuth2" {
		t.Errorf("tok2: got %v, ok=%v; want keyAuth2, true", v, ok)
	}

	// CleanUp tok1; tok2 should remain.
	if err := p.CleanUp("example.com", "tok1", "keyAuth1"); err != nil {
		t.Fatalf("CleanUp(tok1): %v", err)
	}
	if _, ok := p.tokens.Load("tok1"); ok {
		t.Error("tok1 should be deleted after CleanUp")
	}
	if v, ok := p.tokens.Load("tok2"); !ok || v.(tokenEntry).keyAuth != "keyAuth2" {
		t.Errorf("tok2 after tok1 cleanup: got %v, ok=%v; want keyAuth2, true", v, ok)
	}
}

func TestHTTP01Provider_ConcurrentAccess(t *testing.T) {
	p := &HTTP01Provider{}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("tok-%d", i)
			keyAuth := fmt.Sprintf("auth-%d", i)
			if err := p.Present("example.com", token, keyAuth); err != nil {
				t.Errorf("Present(%s): %v", token, err)
			}
			if err := p.CleanUp("example.com", token, keyAuth); err != nil {
				t.Errorf("CleanUp(%s): %v", token, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestChallengeHandler_ServesKeyAuth(t *testing.T) {
	m := &ACMEManager{
		provider: &HTTP01Provider{},
	}
	m.provider.tokens.Store("test-token", tokenEntry{
		keyAuth:   "test-key-auth",
		expiresAt: time.Now().Add(time.Minute),
	})

	handler := m.ChallengeHandler()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-token", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if body := rec.Body.String(); body != "test-key-auth" {
		t.Errorf("body = %q, want test-key-auth", body)
	}
}

func TestChallengeHandler_Returns404ForUnknown(t *testing.T) {
	m := &ACMEManager{
		provider: &HTTP01Provider{},
	}

	handler := m.ChallengeHandler()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestChallengeHandler_Returns404ForEmptyToken(t *testing.T) {
	m := &ACMEManager{
		provider: &HTTP01Provider{},
	}

	handler := m.ChallengeHandler()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestChallengeHandler_Returns404ForWrongPath(t *testing.T) {
	m := &ACMEManager{
		provider: &HTTP01Provider{},
	}

	handler := m.ChallengeHandler()
	req := httptest.NewRequest("GET", "/other/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestChallengeHandler_BeforeInit_NoPanicAnd404(t *testing.T) {
	m := NewACMEManager(&config.ACMEConfig{
		StorageDir: t.TempDir(),
	}, nil, nil)
	handler := m.ChallengeHandler()

	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/not-present", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHTTP01Provider_TTLExpires(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := baseTime
	p := &HTTP01Provider{
		now: func() time.Time { return now },
	}
	m := &ACMEManager{provider: p}

	if err := p.Present("example.com", "tok-expire", "keyAuth-expire"); err != nil {
		t.Fatalf("Present(tok-expire): %v", err)
	}

	// Move beyond TTL and ensure challenge handler treats token as expired.
	now = baseTime.Add(11 * time.Minute)
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/tok-expire", nil)
	rec := httptest.NewRecorder()
	m.ChallengeHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if _, ok := p.tokens.Load("tok-expire"); ok {
		t.Error("expected expired token to be deleted")
	}
}
