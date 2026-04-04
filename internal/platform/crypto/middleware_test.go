package crypto_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// mockPeerDiscovery implements crypto.PeerDiscovery for testing.
type mockPeerDiscovery struct {
	signingCapable map[string]bool
	signingErrors  map[string]error
	publicKeysPEM  map[string]string // keyID -> PEM string
}

type capturedLogRecord struct {
	message string
	level   slog.Level
	attrs   map[string]any
}

type capturedLogHandler struct {
	mu      sync.Mutex
	records []capturedLogRecord
	level   slog.Level
}

type capturedLogHandlerWithAttrs struct {
	parent      *capturedLogHandler
	parentAttrs []slog.Attr
}

func newCapturedLogHandler(level slog.Level) *capturedLogHandler {
	return &capturedLogHandler{level: level}
}

func (h *capturedLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *capturedLogHandler) Handle(_ context.Context, rec slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	attrs := make(map[string]any)
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.records = append(h.records, capturedLogRecord{
		message: rec.Message,
		level:   rec.Level,
		attrs:   attrs,
	})
	return nil
}

func (h *capturedLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &capturedLogHandlerWithAttrs{
		parent:      h,
		parentAttrs: append([]slog.Attr(nil), attrs...),
	}
}

func (h *capturedLogHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *capturedLogHandler) getRecords() []capturedLogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]capturedLogRecord, len(h.records))
	copy(out, h.records)
	return out
}

func (h *capturedLogHandlerWithAttrs) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *capturedLogHandlerWithAttrs) Handle(_ context.Context, rec slog.Record) error {
	h.parent.mu.Lock()
	defer h.parent.mu.Unlock()

	attrs := make(map[string]any)
	for _, attr := range h.parentAttrs {
		attrs[attr.Key] = attr.Value.Any()
	}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.parent.records = append(h.parent.records, capturedLogRecord{
		message: rec.Message,
		level:   rec.Level,
		attrs:   attrs,
	})
	return nil
}

func (h *capturedLogHandlerWithAttrs) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, len(h.parentAttrs)+len(attrs))
	copy(combined, h.parentAttrs)
	copy(combined[len(h.parentAttrs):], attrs)
	return &capturedLogHandlerWithAttrs{
		parent:      h.parent,
		parentAttrs: combined,
	}
}

func (h *capturedLogHandlerWithAttrs) WithGroup(string) slog.Handler {
	return h
}

func (m *mockPeerDiscovery) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	if err, ok := m.signingErrors[host]; ok {
		return false, err
	}
	return m.signingCapable[host], nil
}

func (m *mockPeerDiscovery) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if pem, ok := m.publicKeysPEM[keyID]; ok {
		return pem, nil
	}
	return "", nil
}

func runtimePolicyFromSignature(cfg *config.SignatureConfig) *policy.RuntimePolicy {
	base := config.DevConfig()
	base.Signature = *cfg
	return policy.NewRuntimePolicy(base, nil)
}

func buildContract(
	t *testing.T,
	customProfiles map[string]*peercompat.Profile,
	mappings []peercompat.ProfileMapping,
) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.NewCompiledContract(customProfiles, mappings)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}
	return contract
}

func TestSignatureMiddleware_OffMode(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("off mode should pass all requests, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_RejectsUnsigned(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("strict mode should reject unsigned requests, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_AcceptsSigned(t *testing.T) {
	// Create a key manager and signer
	km := crypto.NewKeyManager("", "https://sender.example.com")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			km.GetKeyID(): km.GetPublicKeyPEM(),
		},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check peer identity was set
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}
		if pi.Authority == "" {
			t.Error("expected non-empty Authority")
		}
		if pi.AuthorityForCompare == "" {
			t.Error("expected non-empty AuthorityForCompare")
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("strict mode should accept signed requests, got status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_LenientMode_AcceptsUnsignedFromNonCapable(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Peer is NOT signing-capable
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com": false},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	// Peer resolver returns the sender host from request body
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("lenient mode should accept unsigned from non-capable peer, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_LenientMode_RejectsUnsignedFromCapable(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Peer IS signing-capable
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com": true},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	// Peer resolver returns the sender host
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("lenient mode should reject unsigned from signing-capable peer, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_RejectsInvalidSignature(t *testing.T) {
	// Create two different key managers
	kmSender := crypto.NewKeyManager("", "https://sender.example.com")
	kmSender.LoadOrGenerate()

	kmAttacker := crypto.NewKeyManager("", "https://attacker.example.com")
	kmAttacker.LoadOrGenerate()

	signer := crypto.NewRFC9421Signer(kmSender)

	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Return the wrong public key
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			kmSender.GetKeyID(): kmAttacker.GetPublicKeyPEM(), // Wrong key!
		},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	signer.SignRequest(req, body)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("should reject invalid signature, got status %d", w.Code)
	}
}

// TestSignatureMiddleware_DefaultPortEquivalence proves scheme-aware comparison:
// a keyId with explicit :443 matches a declared peer without :443 when scheme is https.
func TestSignatureMiddleware_DefaultPortEquivalence(t *testing.T) {
	// Use explicit :443 in the sender's external origin so the keyId includes it.
	km := crypto.NewKeyManager("", "https://sender.example.com:443")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{InboundMode: "strict", AllowMismatch: false}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			km.GetKeyID(): km.GetPublicKeyPEM(),
		},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	// Peer resolver returns "sender.example.com" (without :443).
	// The keyId will contain :443 explicitly.
	// Scheme-aware comparison must treat them as equivalent.
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}
		// AuthorityForCompare should have :443 stripped (default for https)
		if pi.AuthorityForCompare != "sender.example.com" {
			t.Errorf("expected AuthorityForCompare 'sender.example.com', got %q", pi.AuthorityForCompare)
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("default port equivalence: expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_LenientMode_AllowsCapablePeerByProfile(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com": true},
	}
	contract := buildContract(
		t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                 "compat",
				AllowUnsignedInbound: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "sender.example.com", ProfileName: "compat"},
		},
	)

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), contract, pd, "https://receiver.example.com", logger)
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"sender":"user@sender.example.com"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected profile relaxation to allow unsigned request, got %d", w.Code)
	}
}

func TestSignatureMiddleware_LenientMode_AllowsDiscoveryFailureByProfile(t *testing.T) {
	cfg := &config.SignatureConfig{
		InboundMode:      "lenient",
		OnDiscoveryError: "reject",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		signingErrors: map[string]error{
			"sender.example.com": fmt.Errorf("discovery failed"),
		},
	}
	contract := buildContract(
		t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "sender.example.com", ProfileName: "compat"},
		},
	)

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), contract, pd, "https://receiver.example.com", logger)
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"sender":"user@sender.example.com"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected profile-based discovery fail-open, got %d", w.Code)
	}
}

func TestSignatureMiddleware_LenientMode_RejectsDiscoveryFailureWhenUnmatched(t *testing.T) {
	cfg := &config.SignatureConfig{
		InboundMode:      "lenient",
		OnDiscoveryError: "reject",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		signingErrors: map[string]error{
			"sender.example.com": fmt.Errorf("discovery failed"),
		},
	}
	contract := buildContract(
		t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "other.example.com", ProfileName: "compat"},
		},
	)

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), contract, pd, "https://receiver.example.com", logger)
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"sender":"user@sender.example.com"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected unmatched peer discovery failure rejection, got %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_MatchedProfileAllowsMismatch(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{
		InboundMode:      "strict",
		AllowMismatch:    false,
		OnDiscoveryError: "reject",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			km.GetKeyID(): km.GetPublicKeyPEM(),
		},
	}
	contract := buildContract(
		t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                "compat",
				AllowMismatchedHost: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "declared.example.com", ProfileName: "compat"},
		},
	)

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), contract, pd, "https://receiver.example.com", logger)
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "declared.example.com", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@declared.example.com"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected matched profile mismatch relaxation to pass, got %d", w.Code)
	}
}

func TestSignatureMiddleware_LogsCompatibilityDecisionFields(t *testing.T) {
	cfg := &config.SignatureConfig{
		InboundMode:      "lenient",
		OnDiscoveryError: "reject",
	}
	logHandler := newCapturedLogHandler(slog.LevelWarn)
	logger := slog.New(logHandler)
	pd := &mockPeerDiscovery{
		signingErrors: map[string]error{
			"sender.example.com": fmt.Errorf("discovery failed"),
		},
	}
	contract := buildContract(
		t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "sender.example.com", ProfileName: "compat"},
		},
	)

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), contract, pd, "https://receiver.example.com", logger)
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := chimw.RequestID(
		mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
	)

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"sender":"user@sender.example.com"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected profile-based discovery fail-open, got %d", w.Code)
	}

	records := logHandler.getRecords()
	if len(records) == 0 {
		t.Fatal("expected at least one compatibility decision log record")
	}
	record := records[len(records)-1]
	if record.message != "peer discovery failed, allowing unsigned" {
		t.Fatalf("unexpected log message %q", record.message)
	}
	requiredFields := []string{
		"request_id",
		"peer_domain",
		"profile",
		"operation",
		"decision",
		"reason_code",
		"compatibility_scope",
	}
	for _, field := range requiredFields {
		if _, ok := record.attrs[field]; !ok {
			t.Fatalf("compatibility decision log missing %q field", field)
		}
	}
	if record.attrs["peer_domain"] != "sender.example.com" {
		t.Fatalf("expected peer_domain sender.example.com, got %v", record.attrs["peer_domain"])
	}
	if record.attrs["profile"] != "compat" {
		t.Fatalf("expected profile compat, got %v", record.attrs["profile"])
	}
	if record.attrs["operation"] != "unsigned_inbound_discovery" {
		t.Fatalf("expected discovery operation, got %v", record.attrs["operation"])
	}
	if record.attrs["decision"] != "allow" {
		t.Fatalf("expected decision allow, got %v", record.attrs["decision"])
	}
	if record.attrs["reason_code"] != "peer_allow_unsigned_discovery" {
		t.Fatalf("expected profile discovery reason code, got %v", record.attrs["reason_code"])
	}
	if record.attrs["compatibility_scope"] != "scoped" {
		t.Fatalf("expected scoped compatibility scope, got %v", record.attrs["compatibility_scope"])
	}
}

func TestGetPeerIdentity(t *testing.T) {
	// Without peer identity
	ctx := context.Background()
	pi := crypto.GetPeerIdentity(ctx)
	if pi != nil {
		t.Error("expected nil peer identity for empty context")
	}

	// With peer identity
	ctx = context.WithValue(ctx, crypto.PeerIdentityKey, &crypto.PeerIdentity{
		Authority:           "example.com",
		AuthorityForCompare: "example.com",
		Authenticated:       true,
		KeyID:               "https://example.com#key1",
	})
	pi = crypto.GetPeerIdentity(ctx)
	if pi == nil {
		t.Fatal("expected peer identity")
	}
	if pi.Authority != "example.com" {
		t.Errorf("expected authority 'example.com', got %q", pi.Authority)
	}
	if pi.AuthorityForCompare != "example.com" {
		t.Errorf("expected authority_for_compare 'example.com', got %q", pi.AuthorityForCompare)
	}
	if !pi.Authenticated {
		t.Error("expected authenticated=true")
	}
}
