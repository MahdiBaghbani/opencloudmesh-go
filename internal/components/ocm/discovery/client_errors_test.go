// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_ErrorsIsThroughDiscoverWrap(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}

		if !errors.Is(err, discovery.ErrDiscoveryNotFound) {
			t.Fatalf("errors.Is(err, ErrDiscoveryNotFound) = false, err = %v", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/ocm" {
				http.NotFound(w, r)
				return
			}

			w.Header().Set("Content-Type", "application/json")

			if _, err := w.Write([]byte("{not-json")); err != nil {
				t.Errorf("write response: %v", err)
			}
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}

		if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
			t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/ocm" {
				http.NotFound(w, r)
				return
			}

			tshttp.MustEncodeJSON(t, w, map[string]any{
				"enabled":       false,
				"apiVersion":    "1.4.0",
				"resourceTypes": []any{},
				"criteria":      []any{},
			})
		}))
		defer server.Close()

		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected error")
		}

		if !errors.Is(err, discovery.ErrOCMDisabled) {
			t.Fatalf("errors.Is(err, ErrOCMDisabled) = false, err = %v", err)
		}
	})
}
