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

	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestSignatureMiddleware_IfPresent_StrictMode_AllowsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sig.GetPeerIdentity(r.Context()) != nil {
			t.Error("expected no peer identity for unsigned discovery request")
		}

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unsigned discovery request, got %d", w.Code)
	}
}
func TestSignatureMiddleware_RequireSignatureAndPeer_AdvertiseFalse_AllowsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	mw.SetLocalHTTPSigPolicy(true, false)

	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sig.GetPeerIdentity(r.Context()) != nil {
			t.Error("expected no authenticated peer identity for unsigned optional request")
		}

		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when signatures are required but not advertised, got %d: %s", w.Code, w.Body.String())
	}
}
func TestSignatureMiddleware_LabelWithoutTag_IsUnsigned(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	tests := []struct {
		name      string
		requires  bool
		advertise bool
		wantCode  int
	}{
		{
			name:      "advertised requires signature",
			requires:  true,
			advertise: true,
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "not advertised optional",
			requires:  true,
			advertise: false,
			wantCode:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
			mw.SetLocalHTTPSigPolicy(tt.requires, tt.advertise)

			peerResolver := func(_ *http.Request, _ []byte) (string, error) {
				return "sender.example.com", nil
			}
			handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
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
				`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519"`,
				created, km.GetKeyID(),
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

			if w.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantCode == http.StatusUnauthorized {
				got := strings.TrimSpace(w.Body.String())
				if got != "signature required" {
					t.Fatalf("body = %q, want signature required", got)
				}

				if strings.Contains(got, "signature verification failed") {
					t.Fatalf("body = %q, must not be signature verification failed", got)
				}
			}
		})
	}
}
func TestSignatureMiddleware_ForeignSignature_TreatedAsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	tests := []struct {
		name      string
		sigInput  string
		signature string
		mount     func(*sig.SignatureMiddleware) func(http.Handler) http.Handler
	}{
		{
			name:      "foreign label with foreign tag via IfPresent",
			sigInput:  `proxy=("@method" "@target-uri");created=1;keyid="proxy.example.com#key1";tag="proxy"`,
			signature: "proxy=:AAAA:",
			mount: func(mw *sig.SignatureMiddleware) func(http.Handler) http.Handler {
				return mw.VerifyOCMRequestIfPresent()
			},
		},
		{
			name:      "foreign label without tag via RequireSignatureAndPeer optional",
			sigInput:  `proxy=("@method" "@target-uri");created=1;keyid="proxy.example.com#key1"`,
			signature: "proxy=:AAAA:",
			mount: func(mw *sig.SignatureMiddleware) func(http.Handler) http.Handler {
				return mw.VerifyOCMRequestRequireSignatureAndPeer(func(_ *http.Request, _ []byte) (string, error) {
					return "sender.example.com", nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
			mw.SetLocalHTTPSigPolicy(true, false)
			handler := tt.mount(mw)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
			req.Header.Set("Signature-Input", tt.sigInput)
			req.Header.Set("Signature", tt.signature)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for foreign signature treated as unsigned, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}
