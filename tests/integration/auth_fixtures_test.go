// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func loginSubprocessAdmin(t *testing.T, srv *harness.SubprocessServer) string {
	t.Helper()

	if token, _, ok := tryLogin(t, srv.BaseURL, "admin", "admin"); ok {
		return token
	}

	logPath := filepath.Join(srv.TempDir, "server.log")

	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read subprocess log for bootstrap password: %v", err)
	}

	password := extractBootstrapPassword(string(logs))
	if password == "" {
		t.Fatalf("could not find bootstrap admin password in server log:\n%s", logs)
	}

	token, body, ok := tryLogin(t, srv.BaseURL, "admin", password)
	if !ok {
		t.Fatalf("login failed with logged bootstrap password %q: %s", password, body)
	}

	return token
}

func tryLogin(t *testing.T, baseURL, username, password string) (string, string, bool) {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}

	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
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

func extractBootstrapPassword(logs string) string {
	marker := `"password":"`

	start := strings.Index(logs, marker)
	if start == -1 {
		return ""
	}

	start += len(marker)

	end := strings.Index(logs[start:], `"`)
	if end == -1 {
		return ""
	}

	return logs[start : start+end]
}

func createOutgoingShare(t *testing.T, baseURL, token string, payload map[string]any) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal outgoing share payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/shares/outgoing", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create outgoing share request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call outgoing share endpoint: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, string(respBody)
}
