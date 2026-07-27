// Package session provides HTTP helpers for authenticated integration tests.
package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const defaultAdminPassword = "testpassword123"

// Login exchanges credentials for a session bearer token at /api/auth/login.
func Login(client *http.Client, baseURL, username, password string) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}

	if password == "" {
		password = defaultAdminPassword
	}

	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return "", fmt.Errorf("encode login body: %w", err)
	}

	resp, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST login: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort body cleanup; close error is not actionable on an abandoned response

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed: status=%d body=%s", resp.StatusCode, respBody)
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}

	if parsed.Token == "" {
		return "", fmt.Errorf("login returned empty token: %s", respBody)
	}

	return parsed.Token, nil
}

// NewRequest builds an HTTP request with optional JSON body and bearer auth.
func NewRequest(method, baseURL, path, token string, payload any) (*http.Request, error) {
	var body io.Reader

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}

		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return nil, err
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return req, nil
}

// DoJSON sends a request and decodes a JSON response into dst when dst is non-nil.
func DoJSON(client *http.Client, req *http.Request, dst any) (int, []byte, error) {
	if client == nil {
		client = http.DefaultClient
	}

	//nolint:gosec // test-only helper; SSRF is not applicable to test infrastructure
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort body cleanup; close error is not actionable on an abandoned response

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if dst != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, dst); err != nil {
			return resp.StatusCode, raw, fmt.Errorf("decode response: %w", err)
		}
	}

	return resp.StatusCode, raw, nil
}
