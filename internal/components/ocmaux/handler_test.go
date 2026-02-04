package ocmaux_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocmaux"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"

	// Register cache drivers for discovery client
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- HandleFederations tests ---

func TestHandleFederations_NilTrustGroupManager(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("expected JSON array, got parse error: %v\nbody: %s", err, w.Body.String())
	}
	if len(result) != 0 {
		t.Errorf("expected empty array, got %d entries", len(result))
	}
}

func TestHandleFederations_EmptyTrustGroups(t *testing.T) {
	mgr := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", testLogger(), 10*time.Second)
	h := ocmaux.NewAuxHandler(mgr, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("expected JSON array: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty array, got %d entries", len(result))
	}
}

func TestHandleFederations_WithServers(t *testing.T) {
	// Mock discovery server that returns inviteAcceptDialog
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":            true,
				"apiVersion":         "1.2.2",
				"endPoint":           "https://example.com/ocm",
				"inviteAcceptDialog": "/apps/ocm/invite-accept",
				"resourceTypes":      []any{},
				"criteria":           []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer discServer.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	mgr := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", testLogger(), 10*time.Second)
	mgr.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "tg1",
		Enabled:      true,
	})
	mgr.SetCacheForTesting("tg1", []directoryservice.Listing{
		{
			Federation: "ScienceMesh",
			Servers: []directoryservice.Server{
				{URL: discServer.URL, DisplayName: "Test Server"},
			},
		},
	}, time.Now())

	h := ocmaux.NewAuxHandler(mgr, discClient, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	type serverEntry struct {
		DisplayName        string `json:"displayName"`
		URL                string `json:"url"`
		InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"`
	}
	type fedEntry struct {
		Federation string        `json:"federation"`
		Servers    []serverEntry `json:"servers"`
	}

	var result []fedEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v\nbody: %s", err, w.Body.String())
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 federation entry, got %d", len(result))
	}
	if result[0].Federation != "ScienceMesh" {
		t.Errorf("expected federation 'ScienceMesh', got %q", result[0].Federation)
	}
	if len(result[0].Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result[0].Servers))
	}
	srv := result[0].Servers[0]
	if srv.DisplayName != "Test Server" {
		t.Errorf("expected displayName 'Test Server', got %q", srv.DisplayName)
	}
	if srv.URL != discServer.URL {
		t.Errorf("expected URL %q, got %q", discServer.URL, srv.URL)
	}
	// inviteAcceptDialog should be resolved to absolute
	if srv.InviteAcceptDialog == "" {
		t.Error("expected non-empty inviteAcceptDialog")
	}
	if srv.InviteAcceptDialog == "/apps/ocm/invite-accept" {
		t.Errorf("expected absolute URL, got relative: %s", srv.InviteAcceptDialog)
	}
}

func TestHandleFederations_DiscoveryFailureDropsServer(t *testing.T) {
	// Discovery server that always fails
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer discServer.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	mgr := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", testLogger(), 10*time.Second)
	mgr.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "tg1",
		Enabled:      true,
	})
	mgr.SetCacheForTesting("tg1", []directoryservice.Listing{
		{
			Federation: "TestFed",
			Servers: []directoryservice.Server{
				{URL: discServer.URL, DisplayName: "Broken Server"},
			},
		},
	}, time.Now())

	h := ocmaux.NewAuxHandler(mgr, discClient, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	type fedEntry struct {
		Federation string            `json:"federation"`
		Servers    []json.RawMessage `json:"servers"`
	}
	var result []fedEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 federation, got %d", len(result))
	}
	// Server should be silently dropped because discovery failed
	if len(result[0].Servers) != 0 {
		t.Errorf("expected 0 servers (discovery failed), got %d", len(result[0].Servers))
	}
}

func TestHandleFederations_NoDiscoveryClient(t *testing.T) {
	// When discoveryClient is nil, servers are returned without enrichment
	mgr := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", testLogger(), 10*time.Second)
	mgr.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "tg1",
		Enabled:      true,
	})
	mgr.SetCacheForTesting("tg1", []directoryservice.Listing{
		{
			Federation: "TestFed",
			Servers: []directoryservice.Server{
				{URL: "https://server.example.com", DisplayName: "Server"},
			},
		},
	}, time.Now())

	h := ocmaux.NewAuxHandler(mgr, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	type serverEntry struct {
		DisplayName        string `json:"displayName"`
		URL                string `json:"url"`
		InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"`
	}
	type fedEntry struct {
		Federation string        `json:"federation"`
		Servers    []serverEntry `json:"servers"`
	}
	var result []fedEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(result) != 1 || len(result[0].Servers) != 1 {
		t.Fatalf("expected 1 federation with 1 server, got %+v", result)
	}
	if result[0].Servers[0].InviteAcceptDialog != "" {
		t.Errorf("expected no inviteAcceptDialog without discovery client, got %q", result[0].Servers[0].InviteAcceptDialog)
	}
}

func TestHandleFederations_MethodNotAllowed(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/federations", nil)
	w := httptest.NewRecorder()
	h.HandleFederations(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// --- HandleDiscover tests ---

func TestHandleDiscover_MissingBase(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["success"] != false {
		t.Error("expected success=false")
	}
}

func TestHandleDiscover_InvalidBase(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	tests := []struct {
		name  string
		query string
	}{
		{"no scheme", "?base=example.com"},
		{"ftp scheme", "?base=ftp://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/discover"+tt.query, nil)
			w := httptest.NewRecorder()
			h.HandleDiscover(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestHandleDiscover_NoDiscoveryClient(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

func TestHandleDiscover_Success(t *testing.T) {
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":       true,
				"apiVersion":    "1.2.2",
				"endPoint":      "https://example.com/ocm",
				"provider":      "TestProvider",
				"resourceTypes": []any{},
				"criteria":      []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer discServer.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)

	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success   bool `json:"success"`
		Discovery *struct {
			Enabled  bool   `json:"enabled"`
			Provider string `json:"provider"`
		} `json:"discovery"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
	if resp.Discovery == nil {
		t.Fatal("expected discovery object")
	}
	if resp.Discovery.Provider != "TestProvider" {
		t.Errorf("expected provider 'TestProvider', got %q", resp.Discovery.Provider)
	}
}

func TestHandleDiscover_InviteAcceptDialogAbsolute(t *testing.T) {
	// Discovery server that returns a relative inviteAcceptDialog
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":            true,
				"apiVersion":         "1.2.2",
				"endPoint":           "https://remote.example.com/ocm",
				"inviteAcceptDialog": "/apps/ocm/invite-accept",
				"resourceTypes":      []any{},
				"criteria":           []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer discServer.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Success                    bool   `json:"success"`
		InviteAcceptDialogAbsolute string `json:"inviteAcceptDialogAbsolute"`
		Discovery                  *struct {
			InviteAcceptDialog string `json:"inviteAcceptDialog"`
		} `json:"discovery"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
	if resp.InviteAcceptDialogAbsolute == "" {
		t.Error("expected non-empty inviteAcceptDialogAbsolute")
	}
	// The relative path should be resolved against the discovered server URL
	if resp.InviteAcceptDialogAbsolute == "/apps/ocm/invite-accept" {
		t.Error("expected absolute URL, got relative")
	}
}

func TestHandleDiscover_NoInviteAcceptDialog(t *testing.T) {
	// Discovery server that does NOT return inviteAcceptDialog
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":       true,
				"apiVersion":    "1.2.2",
				"endPoint":      "https://example.com/ocm",
				"resourceTypes": []any{},
				"criteria":      []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer discServer.Close()

	httpCfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := ocmaux.NewAuxHandler(nil, discClient, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		InviteAcceptDialogAbsolute string `json:"inviteAcceptDialogAbsolute"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.InviteAcceptDialogAbsolute != "" {
		t.Errorf("expected empty inviteAcceptDialogAbsolute when not in discovery, got %q", resp.InviteAcceptDialogAbsolute)
	}
}

func TestHandleDiscover_MethodNotAllowed(t *testing.T) {
	h := ocmaux.NewAuxHandler(nil, nil, testLogger())

	req := httptest.NewRequest(http.MethodPost, "/discover?base=https://example.com", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
