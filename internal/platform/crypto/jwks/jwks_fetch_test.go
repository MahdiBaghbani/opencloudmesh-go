package jwks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestFetchURL(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwks.WellKnownPath {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	got, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
	if err != nil {
		t.Fatalf("FetchURL: %v", err)
	}

	key, err := got.Find(testJWKSKey1)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	if !pub.Equal(key.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}
}

func TestFetchURL_Errors(t *testing.T) {
	t.Run("404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "status 404") {
			t.Fatalf("FetchURL() error = %v, want status 404", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "decode JSON") {
			t.Fatalf("FetchURL() error = %v, want decode JSON failure", err)
		}
	})

	t.Run("empty key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "empty key set") {
			t.Fatalf("FetchURL() error = %v, want empty key set", err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		_, err := jwks.FetchURL(context.Background(), nil, "https://example.com/.well-known/jwks.json")
		if !errors.Is(err, jwks.ErrNilHTTPClient) {
			t.Fatalf("FetchURL() error = %v, want ErrNilHTTPClient", err)
		}
	})

	t.Run("response too large", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("a"), 64))
		}))
		defer srv.Close()

		_, err := jwks.FetchURLLimited(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath, 32)
		if !errors.Is(err, jwks.ErrResponseTooLarge) {
			t.Fatalf("FetchURLLimited() error = %v, want ErrResponseTooLarge", err)
		}
	})
}
