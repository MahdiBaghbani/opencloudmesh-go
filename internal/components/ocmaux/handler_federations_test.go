package ocmaux_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocmaux"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

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
	var serverURL string

	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":            true,
				"apiVersion":         "1.4.0",
				"endPoint":           serverURL + "/ocm",
				"inviteAcceptDialog": "/apps/ocm/invite-accept",
				"resourceTypes":      []any{},
				"criteria":           []any{},
			})

			return
		}

		http.NotFound(w, r)
	}))
	defer discServer.Close()

	serverURL = discServer.URL

	httpCfg := tshttp.PermissiveConfig()
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
		Status             *struct {
			Discovery  string `json:"discovery"`
			ReasonCode string `json:"reasonCode,omitempty"`
		} `json:"status,omitempty"`
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

	if srv.InviteAcceptDialog == "" {
		t.Error("expected non-empty inviteAcceptDialog")
	}

	if srv.InviteAcceptDialog == "/apps/ocm/invite-accept" {
		t.Errorf("expected absolute URL, got relative: %s", srv.InviteAcceptDialog)
	}

	if srv.Status != nil {
		t.Errorf("expected no status on successful enrichment, got %+v", srv.Status)
	}
}

func TestHandleFederations_DiscoveryFailureKeepsServerWithStatus(t *testing.T) {
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer discServer.Close()

	httpCfg := tshttp.PermissiveConfig()
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

	type serverEntry struct {
		DisplayName        string `json:"displayName"`
		URL                string `json:"url"`
		InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"`
		Status             *struct {
			Discovery  string `json:"discovery"`
			ReasonCode string `json:"reasonCode,omitempty"`
		} `json:"status,omitempty"`
	}

	type fedEntry struct {
		Federation string        `json:"federation"`
		Servers    []serverEntry `json:"servers"`
	}

	var result []fedEntry
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 federation, got %d", len(result))
	}

	if len(result[0].Servers) != 1 {
		t.Fatalf("expected 1 server kept after discovery failure, got %d", len(result[0].Servers))
	}

	srv := result[0].Servers[0]
	if srv.DisplayName != "Broken Server" {
		t.Errorf("expected displayName 'Broken Server', got %q", srv.DisplayName)
	}

	if srv.URL != discServer.URL {
		t.Errorf("expected URL %q, got %q", discServer.URL, srv.URL)
	}

	if srv.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog, got %q", srv.InviteAcceptDialog)
	}

	if srv.Status == nil {
		t.Fatal("expected status object on discovery failure")
	}

	if srv.Status.Discovery != "failed" {
		t.Errorf("expected discovery status 'failed', got %q", srv.Status.Discovery)
	}

	if srv.Status.ReasonCode != reason.PeerDiscoveryFailed {
		t.Errorf("expected reasonCode %q, got %q", reason.PeerDiscoveryFailed, srv.Status.ReasonCode)
	}
}

func TestHandleFederations_NoDiscoveryClient(t *testing.T) {
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
