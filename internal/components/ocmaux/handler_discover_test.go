package ocmaux

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func discoverTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestHandleDiscover_BareHostSuccess(t *testing.T) {
	var serverURL string

	discServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":            true,
				"apiVersion":         "1.4.0",
				"endPoint":           serverURL + "/ocm",
				"provider":           "TestProvider",
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

	host := strings.TrimPrefix(discServer.URL, "https://")

	httpCfg := tshttp.PermissiveConfig()
	httpCfg.InsecureSkipVerify = true
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+host, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleDiscover_PastedPathNormalizesToOrigin(t *testing.T) {
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

	base := serverURL + "/apps/files/files/123"

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+base, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleDiscover_SSRFBlockedFriendlyResponse(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	httpCfg.SSRF.Mode = "strict"
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base=http://127.0.0.1:8080", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp DiscoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Success {
		t.Fatal("expected success=false")
	}

	if resp.ReasonCode != reason.SSRFBlocked {
		t.Fatalf("reasonCode = %q, want %q", resp.ReasonCode, reason.SSRFBlocked)
	}

	if resp.Error != discoverMsgSSRFBlocked {
		t.Fatalf("error = %q, want friendly message", resp.Error)
	}

	if strings.Contains(resp.Error, "private IP") || strings.Contains(resp.Error, "CIDR") {
		t.Fatalf("user-facing error leaked SSRF details: %q", resp.Error)
	}
}

func TestHandleDiscover_DNSFailureReason(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()
	httpCfg.SSRF.Mode = "strict"
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base=https://this-domain-does-not-exist-12345.invalid", nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp DiscoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ReasonCode != discoverReasonDNSUnresolvable {
		t.Fatalf("reasonCode = %q, want %q", resp.ReasonCode, discoverReasonDNSUnresolvable)
	}

	if resp.Error != discoverMsgDNSFailed {
		t.Fatalf("error = %q, want friendly DNS message", resp.Error)
	}
}

func TestHandleDiscover_InvalidURLReason(t *testing.T) {
	h := NewAuxHandler(nil, nil, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base=ftp://example.com", nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp DiscoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ReasonCode != discoverReasonInvalidURL {
		t.Fatalf("reasonCode = %q, want %q", resp.ReasonCode, discoverReasonInvalidURL)
	}
}

func TestHandleDiscover_NoOCMDiscoveryReason(t *testing.T) {
	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer discServer.Close()

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+discServer.URL, nil)
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp DiscoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ReasonCode != discoverReasonNoOCMDiscovery {
		t.Fatalf("reasonCode = %q, want %q", resp.ReasonCode, discoverReasonNoOCMDiscovery)
	}

	if resp.Error != discoverMsgNoOCM {
		t.Fatalf("error = %q, want %q", resp.Error, discoverMsgNoOCM)
	}
}

func TestHandleDiscover_NoInviteAcceptDialogReason(t *testing.T) {
	var serverURL string

	discServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":       true,
				"apiVersion":    "1.4.0",
				"endPoint":      serverURL + "/ocm",
				"resourceTypes": []any{},
				"criteria":      []any{},
			})

			return
		}

		http.NotFound(w, r)
	}))
	defer discServer.Close()

	serverURL = discServer.URL

	httpCfg := tshttp.PermissiveConfig()
	discClient := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
	h := NewAuxHandler(nil, discClient, discoverTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/discover?base="+discServer.URL, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	h.HandleDiscover(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	var resp DiscoverResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Success {
		t.Fatal("expected success=false")
	}

	if resp.ReasonCode != discoverReasonNoInviteAcceptDialog {
		t.Fatalf("reasonCode = %q, want %q", resp.ReasonCode, discoverReasonNoInviteAcceptDialog)
	}

	if resp.Error != discoverMsgNoInviteAcceptDialog {
		t.Fatalf("error = %q, want %q", resp.Error, discoverMsgNoInviteAcceptDialog)
	}
}
