// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestOutgoingSharePolicyDifferences(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	trueVal := true
	falseVal := false
	tests := []struct {
		name         string
		peerPolicy   string
		wantStatus   int
		wantPosts    int32
		wantMustExch *bool
	}{
		{
			name:       "strict rejects capable non-strict peer",
			peerPolicy: "strict",
			wantStatus: reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantPosts:  0,
		},
		{
			name:         "prefer-strict sends must-exchange-token",
			peerPolicy:   "prefer-strict",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &trueVal,
		},
		{
			name:         "legacy sends without must-exchange-token",
			peerPolicy:   "legacy",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &falseVal,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest needs its own server because policy is frozen at startup.
			ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
				cfg.PeerPolicy = tc.peerPolicy
			})
			defer ts.Stop(t)

			token := loginAdmin(t, ts.BaseURL, "admin", "admin")

			shareFile, err := os.CreateTemp("/tmp", "policy-diff-share-*")
			if err != nil {
				t.Fatalf("failed to create temp share file: %v", err)
			}
			if _, err := shareFile.WriteString("policy diff integration payload"); err != nil {
				t.Fatalf("failed to seed temp share file: %v", err)
			}
			if err := shareFile.Close(); err != nil {
				t.Fatalf("failed to close temp share file: %v", err)
			}
			t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

			receiver, postCount, mustExchangeFlag := startCapableNonStrictReceiver(t)
			defer receiver.Close()

			receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
			status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
				"receiverDomain": receiverDomain,
				"shareWith":      "bob@" + receiverDomain,
				"localPath":      shareFile.Name(),
				"permissions":    []string{"read"},
			})

			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, status, body)
			}

			if got := postCount.Load(); got != tc.wantPosts {
				t.Fatalf("expected receiver POST count %d, got %d", tc.wantPosts, got)
			}

			if tc.wantMustExch != nil {
				gotFlag := mustExchangeFlag.Load()
				if gotFlag == -1 {
					t.Fatal("receiver did not capture must-exchange-token state")
				}
				gotMust := gotFlag == 1
				if gotMust != *tc.wantMustExch {
					t.Fatalf("must-exchange-token mismatch: got %v, want %v", gotMust, *tc.wantMustExch)
				}
			}
		})
	}
}

func TestWebDAVStrictShareRejectsSharedSecretWhenLocalNotStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	token := loginAdmin(t, ts.BaseURL, "admin", "admin")
	d := deps.GetDeps()
	if d == nil || d.Config == nil || d.OpenCloudMeshPolicy == nil || d.OutgoingShareRepo == nil {
		t.Fatal("shared deps are not fully initialized")
	}
	if d.OpenCloudMeshPolicy.Evaluate().RequiresTokenExchange {
		t.Fatal("test requires local policy strictness=false")
	}

	shareFile, err := os.CreateTemp("/tmp", "webdav-strict-share-*")
	if err != nil {
		t.Fatalf("failed to create temp share file: %v", err)
	}
	if _, err := shareFile.WriteString("strict-share shared-secret rejection proof"); err != nil {
		t.Fatalf("failed to write temp share file: %v", err)
	}
	if err := shareFile.Close(); err != nil {
		t.Fatalf("failed to close temp share file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

	receiver, _, _ := startCapableNonStrictReceiver(t)
	defer receiver.Close()

	receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
	status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
		"receiverDomain": receiverDomain,
		"shareWith":      "bob@" + receiverDomain,
		"localPath":      shareFile.Name(),
		"permissions":    []string{"read"},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201 from outgoing share create, got %d: %s", status, body)
	}

	var created struct {
		ProviderID string `json:"providerId"`
		WebDAVID   string `json:"webdavId"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode outgoing share response: %v", err)
	}
	if created.ProviderID == "" || created.WebDAVID == "" {
		t.Fatalf("outgoing share response missing providerId/webdavId: %s", body)
	}

	share, err := d.OutgoingShareRepo.GetByProviderID(nil, created.ProviderID)
	if err != nil {
		t.Fatalf("failed to load created outgoing share: %v", err)
	}
	if !share.MustExchangeToken {
		t.Fatal("expected created share MustExchangeToken=true for prefer-strict policy")
	}

	fileName := filepath.Base(shareFile.Name())
	webdavURL := ts.BaseURL + "/webdav/ocm/" + created.WebDAVID + "/" + url.PathEscape(fileName)
	req, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("failed to create webdav request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call webdav endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 for shared-secret access to strict share, got %d: %s", resp.StatusCode, respBody)
	}
}

func startCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				Criteria:      []string{},
				TokenEndPoint: srv.URL + "/ocm/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		case "/ocm/shares":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var req spec.NewShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			postCount.Add(1)
			mustExchange := req.Protocol.WebDAV != nil &&
				req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken)
			if mustExchange {
				mustExchangeFlag.Store(1)
			} else {
				mustExchangeFlag.Store(0)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, postCount, mustExchangeFlag
}
