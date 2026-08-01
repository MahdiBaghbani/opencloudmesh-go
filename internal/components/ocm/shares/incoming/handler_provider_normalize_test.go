// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// unnormalizableProvider parses as an OCM address provider but fails
// hostport.Normalize (space in hostname).
const unnormalizableProvider = "bad host"

func TestCreateShare_Unauthenticated_RejectsUnnormalizableProviders(t *testing.T) {
	const validHost = "sender.example.com"

	tests := []struct {
		name        string
		ownerHost   string
		senderHost  string
		providerID  string
		lookupHosts []string
	}{
		{
			name:       "owner normalize failure",
			ownerHost:  unnormalizableProvider,
			senderHost: validHost,
			providerID: "unauth-owner-normalize-fail",
			lookupHosts: []string{
				validHost,
				unnormalizableProvider,
			},
		},
		{
			name:        "sender normalize failure",
			ownerHost:   validHost,
			senderHost:  unnormalizableProvider,
			providerID:  "unauth-sender-normalize-fail",
			lookupHosts: []string{unnormalizableProvider},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := tsrepos.OpenMemory(t).IncomingShares
			partyRepo := setupTestPartyRepo(t)
			handler := newTestHandler(repo, partyRepo)

			body := validShareBodyWithOwnerAndSenderHosts(
				"alice@localhost:9200",
				tt.ownerHost,
				tt.senderHost,
				tt.providerID,
			)
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/ocm/shares",
				bytes.NewBufferString(body),
			)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			handler.CreateShare(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
			}

			var resp spec.OCMErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}

			if resp.Message != "UNTRUSTED_PROVIDER" {
				t.Errorf("expected UNTRUSTED_PROVIDER, got %q", resp.Message)
			}

			for _, host := range tt.lookupHosts {
				if _, err := repo.GetByProviderID(context.Background(), host, tt.providerID); err == nil {
					t.Fatalf("expected no share persisted under %q after normalize failure", host)
				}
			}
		})
	}
}

func TestCreateShare_UnauthenticatedOwnerHostDefaultPortStripped(t *testing.T) {
	const (
		normalizedHost = "relay.example.com"
		rawOwnerHost   = "relay.example.com:443"
		providerID     = "unauth-owner-default-port-stripped"
	)

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler := newTestHandler(repo, partyRepo)

	body := validShareBodyWithOwnerAndSenderHosts(
		"alice@localhost:9200",
		rawOwnerHost,
		normalizedHost,
		providerID,
	)
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/ocm/shares",
		bytes.NewBufferString(body),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByProviderID(context.Background(), normalizedHost, providerID)
	if err != nil {
		t.Fatalf("expected persisted share, got error: %v", err)
	}

	if stored.OwnerHost != normalizedHost {
		t.Fatalf("OwnerHost = %q, want normalized %q", stored.OwnerHost, normalizedHost)
	}

	if stored.OwnerHost == rawOwnerHost {
		t.Fatalf("OwnerHost kept raw default-port form %q", stored.OwnerHost)
	}
}

func TestCreateShare_Authenticated_RejectsUnnormalizableOwnerProvider(t *testing.T) {
	const (
		authority  = "relay.example.com"
		providerID = "auth-owner-normalize-fail"
	)

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler := newTestHandler(repo, partyRepo)

	body := validShareBodyWithOwnerAndSenderHosts(
		"alice@localhost:9200",
		unnormalizableProvider,
		authority,
		providerID,
	)
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/ocm/shares",
		bytes.NewBufferString(body),
	)
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authority,
		AuthorityForCompare: authority,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if resp.Message != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", resp.Message)
	}

	if _, err := repo.GetByProviderID(context.Background(), authority, providerID); err == nil {
		t.Fatal("expected no share persisted for unnormalizable owner provider")
	}

	if _, err := repo.GetByProviderID(context.Background(), unnormalizableProvider, providerID); err == nil {
		t.Fatal("expected no share persisted under raw unnormalizable owner host")
	}
}
