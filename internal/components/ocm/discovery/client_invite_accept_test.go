// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_NormalizesRelativeInviteAcceptDialog(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}

		raw := validDiscoveryPayload(serverURL, map[string]any{
			"inviteAcceptDialog": "/apps/ocm/invite-accept",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	want := strings.TrimSuffix(server.URL, "/") + "/apps/ocm/invite-accept"
	if disc.InviteAcceptDialog != want {
		t.Errorf("InviteAcceptDialog = %q, want %q", disc.InviteAcceptDialog, want)
	}
}

func TestClientDiscover_NormalizesRelativeInviteAcceptDialogWithoutEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(_ string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}

		raw := map[string]any{
			"enabled":            true,
			"apiVersion":         "1.4.0",
			"resourceTypes":      []any{},
			"criteria":           []any{},
			"inviteAcceptDialog": "apps/ocm/invite-accept",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error when endPoint is missing")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityInviteAcceptDialog(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}

		raw := validDiscoveryPayload(serverURL, map[string]any{
			"inviteAcceptDialog": "https://custom.example.com/accept",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority inviteAcceptDialog")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}
