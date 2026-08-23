// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorpeer

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestStart_ServesDiscoveryAndJWKS(t *testing.T) {
	t.Parallel()

	peer := Start(t, Options{})
	client := peer.HTTPClient()

	status, raw := getBytes(t, client, peer.URL+discoveryPath)
	if status != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", status)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(raw, &disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	if !disc.Enabled {
		t.Fatal("expected enabled discovery")
	}

	if disc.APIVersion != spec.APIVersionPin {
		t.Fatalf("apiVersion = %q, want %q", disc.APIVersion, spec.APIVersionPin)
	}

	jwksStatus, _ := getBytes(t, client, peer.URL+jwksPath)
	if jwksStatus != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", jwksStatus)
	}

	if peer.Host == "" || peer.Signer == nil {
		t.Fatal("expected host and signer")
	}
}

func TestStart_FailDiscoveryReturns500(t *testing.T) {
	t.Parallel()

	peer := Start(t, Options{FailDiscovery: true})
	client := peer.HTTPClient()

	status, _ := getBytes(t, client, peer.URL+discoveryPath)
	if status != http.StatusInternalServerError {
		t.Fatalf("discovery status = %d, want 500", status)
	}

	jwksStatus, _ := getBytes(t, client, peer.URL+jwksPath)
	if jwksStatus != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", jwksStatus)
	}

	otherStatus, _ := getBytes(t, client, peer.URL+"/not-discovery")
	if otherStatus != http.StatusNotFound {
		t.Fatalf("other status = %d, want 404", otherStatus)
	}
}

func getBytes(t *testing.T, client *http.Client, rawURL string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", rawURL, err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // closed by tshttp.MustClose; bodyclose cannot trace the helper
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer tshttp.MustClose(t, resp.Body)

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawURL, err)
	}

	return resp.StatusCode, raw
}
