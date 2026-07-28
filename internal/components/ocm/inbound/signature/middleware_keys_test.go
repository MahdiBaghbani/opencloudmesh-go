package signature_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestSignatureMiddleware_VerifiedPathfulKeyID_Returns401(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	pathfulKid := "sender.example.com/ocm#key1"
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			pathfulKid: resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on pathful keyId after verify")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	created := time.Now().Unix()
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
		created, pathfulKid,
	)
	req.Header.Set("Signature-Input", sigInput)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")

	base, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}

	fullBase := base + fmt.Sprintf("\"@signature-params\": %s", paramsRaw)

	sigBytes, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sigBytes)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for pathful keyId after verify, got %d: %s", w.Code, w.Body.String())
	}
}
func TestSignatureMiddleware_VerifiedUnnormalizableKeyID_Returns401(t *testing.T) {
	// keyId "[]#key1" is rejected during authority normalization.
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	badKid := "[]#key1"
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			badKid: resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run when keyId authority cannot be normalized")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	created := time.Now().Unix()
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519";tag="ocm"`,
		created, badKid,
	)
	req.Header.Set("Signature-Input", sigInput)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")

	base, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}

	fullBase := base + fmt.Sprintf("\"@signature-params\": %s", paramsRaw)

	sigBytes, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sigBytes)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when authorityForCompareFromKid fails, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "invalid signature keyId") {
		t.Fatalf("body = %q, want invalid signature keyId", w.Body.String())
	}
}
