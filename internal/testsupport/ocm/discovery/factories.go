// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ocmdiscovery "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

const (
	defaultInlineKeyServerURL = "https://peer.example.com"
	defaultInlineKeyID        = "https://peer.example.com/ocm#test-key"
)

// Option configures NewTestClient. Base URL is not an option: discovery.Client
// has no stored base URL; callers pass it to Discover separately.
type Option func(*clientOptions)

type clientOptions struct {
	httpClient *httpclient.Client
	cache      cache.Cache
}

// WithHTTPClient overrides the outbound HTTP client wired into the discovery client.
func WithHTTPClient(c *httpclient.Client) Option {
	return func(o *clientOptions) {
		o.httpClient = c
	}
}

// WithCache overrides the discovery cache. Nil keeps discovery.NewClient defaults.
func WithCache(c cache.Cache) Option {
	return func(o *clientOptions) {
		o.cache = c
	}
}

// NewTestClient builds a discovery.Client with permissive outbound HTTP defaults.
// Nil cache is replaced with the default in-memory cache inside discovery.NewClient.
func NewTestClient(t testing.TB, opts ...Option) *ocmdiscovery.Client {
	t.Helper()

	o := clientOptions{
		httpClient: httpclient.New(tshttp.PermissiveConfig(), nil),
	}
	for _, opt := range opts {
		opt(&o)
	}
	return ocmdiscovery.NewClient(o.httpClient, o.cache)
}

// InlineKeyDiscoveryDoc builds a raw discovery JSON document carrying a singular
// inline publicKey entry, mirroring discovery_test inlineKeyDiscoveryPayload with
// shape "singular", apiVersion spec.APIVersionPin, and a fixed peer base URL.
func InlineKeyDiscoveryDoc(t testing.TB, publicKeyPEM string) map[string]any {
	t.Helper()

	endpoint := strings.TrimSuffix(defaultInlineKeyServerURL, "/") + "/ocm"
	return map[string]any{
		"enabled":       true,
		"apiVersion":    spec.APIVersionPin,
		"endPoint":      endpoint,
		"resourceTypes": []any{},
		"criteria":      []any{},
		"capabilities":  []string{spec.CapabilityHTTPSig},
		"publicKey": map[string]string{
			"keyId":        defaultInlineKeyID,
			"publicKeyPem": publicKeyPEM,
		},
	}
}

// NewDiscoveryTestServer serves doc at /.well-known/ocm and returns the server plus cleanup.
// The served document endPoint is rewritten to match the httptest server authority so
// callers can compose InlineKeyDiscoveryDoc (or any doc with a placeholder endpoint)
// without conflicting with the dynamic server URL.
func NewDiscoveryTestServer(t testing.TB, doc map[string]any) (*httptest.Server, func()) {
	t.Helper()

	payload := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		payload[k] = v
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}

		served := make(map[string]any, len(payload)+1)
		for k, v := range payload {
			served[k] = v
		}
		baseURL := "http://" + r.Host
		served["endPoint"] = strings.TrimSuffix(baseURL, "/") + "/ocm"

		body, err := json.Marshal(served)
		if err != nil {
			panic("marshal discovery doc: " + err.Error())
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			panic("write discovery doc: " + err.Error())
		}
	}))
	srv.Start()

	cleanup := func() { srv.Close() }
	t.Cleanup(cleanup)
	return srv, cleanup
}
