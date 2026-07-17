// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	tsds "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestDirectoryServiceJWSFeedsFederations verifies a hermetic HTTPS Directory Service
// JWS listing is fetched, cached, and exposed through /ocm-aux/federations with
// discovery enrichment status on failed peers.
func TestDirectoryServiceJWSFeedsFederations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	goodPeer := startOCMPeerWithInviteDialog(t)
	defer goodPeer.Close()

	badPeer := startBrokenOCMPeer(t)
	defer badPeer.Close()

	fixture := tsds.GenerateEd25519Fixture(t)
	listing := directoryservice.Listing{
		Federation: "IntegrationFed",
		Servers: []directoryservice.Server{
			{URL: goodPeer.URL, DisplayName: "Good Peer"},
			{URL: badPeer.URL, DisplayName: "Bad Peer"},
		},
	}
	jwsBody := fixture.SignListingCompact(t, listing)

	dsServer := tsds.StartHTTPSDirectoryService(t, jwsBody)
	defer dsServer.Close()

	trustGroup := peertrust.TrustGroupConfig{
		TrustGroupID:      "ds-integration",
		Enabled:           true,
		EnforceMembership: false,
		DirectoryServices: []directoryservice.EndpointConfig{
			{URL: dsServer.URL, Enabled: true, Verification: "required"},
		},
		Keys: []directoryservice.VerificationKey{fixture.VerificationKey()},
	}
	trustGroupJSON, err := json.Marshal(trustGroup)
	if err != nil {
		t.Fatalf("marshal trust group: %v", err)
	}

	// global_enforce=true satisfies the scoped guardrail (dev preset resolves
	// compatibility_scope=scoped, which requires peer_trust.policy.global_enforce=true
	// whenever peer trust is enabled).
	// The trust group's own EnforceMembership=false above still controls
	// whether membership is actually checked.
	extraConfig := `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.policy]
global_enforce = true

[peer_trust.membership_cache]
ttl_seconds = 0
max_stale_seconds = 600
`

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "ds-federations-test",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
		ExtraFiles: map[string]string{
			"trust-group.json": string(trustGroupJSON),
		},
		ExtraConfig: extraConfig,
	})
	defer srv.Stop(t)

	federationsURL := srv.BaseURL + "/ocm-aux/federations"
	result, err := pollFederations(t, federationsURL, 15*time.Second)
	if err != nil {
		srv.DumpLogs(t)
		t.Fatal(err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 federation, got %d: %+v", len(result), result)
	}
	if result[0].Federation != "IntegrationFed" {
		t.Errorf("expected federation IntegrationFed, got %q", result[0].Federation)
	}
	if len(result[0].Servers) != 2 {
		t.Fatalf("expected 2 servers from directory listing, got %d", len(result[0].Servers))
	}

	serversByURL := map[string]federationServerEntry{}
	for _, s := range result[0].Servers {
		serversByURL[s.URL] = s
	}

	good, ok := serversByURL[goodPeer.URL]
	if !ok {
		t.Fatalf("missing good peer %q in response", goodPeer.URL)
	}
	if good.DisplayName != "Good Peer" {
		t.Errorf("good peer displayName = %q, want Good Peer", good.DisplayName)
	}
	if good.InviteAcceptDialog == "" {
		t.Error("expected inviteAcceptDialog on good peer")
	}
	if good.Status != nil {
		t.Errorf("expected no status on enriched good peer, got %+v", good.Status)
	}

	bad, ok := serversByURL[badPeer.URL]
	if !ok {
		t.Fatalf("missing bad peer %q in response", badPeer.URL)
	}
	if bad.DisplayName != "Bad Peer" {
		t.Errorf("bad peer displayName = %q, want Bad Peer", bad.DisplayName)
	}
	if bad.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog on bad peer, got %q", bad.InviteAcceptDialog)
	}
	if bad.Status == nil {
		t.Fatal("expected status on bad peer after discovery failure")
	}
	if bad.Status.Discovery != "failed" {
		t.Errorf("expected discovery status failed, got %q", bad.Status.Discovery)
	}
	if bad.Status.ReasonCode != reason.PeerDiscoveryFailed {
		t.Errorf("expected reasonCode %q, got %q", reason.PeerDiscoveryFailed, bad.Status.ReasonCode)
	}
}

type federationServerEntry struct {
	DisplayName        string `json:"displayName"`
	URL                string `json:"url"`
	InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"`
	Status             *struct {
		Discovery  string `json:"discovery"`
		ReasonCode string `json:"reasonCode,omitempty"`
	} `json:"status,omitempty"`
}

type federationEntry struct {
	Federation string                  `json:"federation"`
	Servers    []federationServerEntry `json:"servers"`
}

func pollFederations(t *testing.T, url string, timeout time.Duration) ([]federationEntry, error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var result []federationEntry
		decodeErr := json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr == nil && len(result) > 0 && len(result[0].Servers) > 0 {
			return result, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for federations from %s", url)
}

func startOCMPeerWithInviteDialog(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":            true,
			"apiVersion":         "1.4.0",
			"endPoint":           srv.URL + "/ocm",
			"inviteAcceptDialog": "/apps/ocm/invite-accept",
			"resourceTypes":      []any{},
			"criteria":           []any{},
		})
	}))
	return srv
}

func startBrokenOCMPeer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
}
