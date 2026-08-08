// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func loginSubprocessAdmin(t *testing.T, srv *harness.SubprocessServer) string {
	t.Helper()

	if token, _, ok := tryLogin(t, srv.BaseURL, "admin", "admin"); ok {
		return token
	}

	password, err := extractBootstrapPassword(srv.TempDir)
	if err != nil {
		t.Fatalf("read bootstrap admin password file: %v", err)
	}

	if password == "" {
		t.Fatalf("could not find bootstrap admin password file in %s", srv.TempDir)
	}

	token, body, ok := tryLogin(t, srv.BaseURL, "admin", password)
	if !ok {
		t.Fatalf("login failed with bootstrap password from file %q: %s", filepath.Join(srv.TempDir, "bootstrap-admin-password"), body)
	}

	return token
}

func tryLogin(t *testing.T, baseURL, username, password string) (string, string, bool) {
	t.Helper()

	reqBody := tshttp.MustMarshalJSON(t, map[string]string{
		"username": username,
		"password": password,
	})

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		baseURL+"/api/auth/login",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("failed to build login request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", string(body), false
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}

	if parsed.Token == "" {
		return "", string(body), false
	}

	return parsed.Token, string(body), true
}

func extractBootstrapPassword(tempDir string) (string, error) {
	path := filepath.Join(tempDir, "bootstrap-admin-password")

	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}

		return "", fmt.Errorf("tests: read bootstrap password: %w", err)
	}

	return strings.TrimSpace(string(content)), nil
}

func createOutgoingShare(t *testing.T, baseURL, token string, payload map[string]any) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal outgoing share payload: %v", err)
	}

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		baseURL+"/api/shares/outgoing",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("failed to create outgoing share request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call outgoing share endpoint: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return resp.StatusCode, string(respBody)
}
