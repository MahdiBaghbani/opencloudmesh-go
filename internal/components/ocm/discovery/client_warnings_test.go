package discovery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestClientDiscover_FreshFetchOnlyLogsWarnings(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"apiVersion": "1.2.2",
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw)
	})

	c := cache.NewDefault()
	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), c)
	client.SetLogger(logger)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}
	if !hasWarningSubstring(disc.Warnings, "differs from pin") {
		t.Fatalf("expected differs-from-pin warning in result, got %v", disc.Warnings)
	}
	firstLog := buf.String()
	if !strings.Contains(firstLog, "discovery warning") {
		t.Fatalf("fresh fetch log missing discovery warning marker, got %q", firstLog)
	}
	if !strings.Contains(firstLog, "differs from pin") {
		t.Fatalf("fresh fetch log missing warning text, got %q", firstLog)
	}

	buf.Reset()
	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if !hasWarningSubstring(disc2.Warnings, "differs from pin") {
		t.Fatalf("cache hit missing warning in result, got %v", disc2.Warnings)
	}
	if buf.Len() != 0 {
		t.Fatalf("cache hit logged warnings again: %q", buf.String())
	}
}

func TestClientDiscover_WarningsOwnershipAndJSONOmission(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"apiVersion": "1.3.0",
			"resourceTypes": []any{
				map[string]any{
					"name":       "file",
					"shareTypes": []string{"user"},
					"protocols": map[string]any{
						"talk": map[string]string{"uri": "talk-v1"},
					},
				},
			},
		})
		json.NewEncoder(w).Encode(raw)
	})

	c := cache.NewDefault()
	client := discovery.NewClient(httpclient.New(httpCfg, nil), c)

	disc1, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("first Discover failed: %v", err)
	}
	if len(disc1.Warnings) < 2 {
		t.Fatalf("expected apiVersion and protocol warnings, got %v", disc1.Warnings)
	}

	out, err := json.Marshal(disc1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "Warnings") || strings.Contains(string(out), "differs from pin") {
		t.Fatalf("marshaled discovery must omit Warnings, got %s", out)
	}

	disc2, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("second Discover failed: %v", err)
	}
	if len(disc2.Warnings) != len(disc1.Warnings) {
		t.Fatalf("cache hit warnings len = %d, want %d (no duplicate accumulation)", len(disc2.Warnings), len(disc1.Warnings))
	}
}
