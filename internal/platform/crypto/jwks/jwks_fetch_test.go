// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestFetchURL(t *testing.T) {
	t.Parallel()
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tshttp.WriteJSON(w, set)
	}))
	defer srv.Close()

	got, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+"/jwks")
	if err != nil {
		t.Fatalf("FetchURL: %v", err)
	}

	key, err := got.ResolveExactKeyID(testJWKSKey1)
	if err != nil {
		t.Fatalf("ResolveExactKeyID: %v", err)
	}

	gotPub, ok := key.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !pub.Equal(gotPub) {
		t.Fatal("key mismatch")
	}
}

func TestFetchURL_Errors(t *testing.T) {
	t.Parallel()
	t.Run("404", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+"/jwks")
		if err == nil || !strings.Contains(err.Error(), "status 404") {
			t.Fatalf("FetchURL() error = %v, want status 404", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustWrite(t, w, []byte(`{"keys":[`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+"/jwks")
		if err == nil || !strings.Contains(err.Error(), "decode JSON") {
			t.Fatalf("FetchURL() error = %v, want decode JSON failure", err)
		}
	})

	t.Run("empty key set", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustWrite(t, w, []byte(`{"keys":[]}`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+"/jwks")
		if err == nil || !strings.Contains(err.Error(), "empty key set") {
			t.Fatalf("FetchURL() error = %v, want empty key set", err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		t.Parallel()

		_, err := jwks.FetchURL(context.Background(), nil, "https://example.com/jwks")
		if !errors.Is(err, jwks.ErrNilHTTPClient) {
			t.Fatalf("FetchURL() error = %v, want ErrNilHTTPClient", err)
		}
	})

	t.Run("response too large", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustWrite(t, w, bytes.Repeat([]byte("a"), 64))
		}))
		defer srv.Close()

		_, err := jwks.FetchURLLimited(context.Background(), srv.Client(), srv.URL+"/jwks", 32)
		if !errors.Is(err, jwks.ErrResponseTooLarge) {
			t.Fatalf("FetchURLLimited() error = %v, want ErrResponseTooLarge", err)
		}
	})
}
