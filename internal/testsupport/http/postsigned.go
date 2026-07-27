package http

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

// PostSignedJSON marshals body to JSON, builds an HTTP request, signs it with
// signer, executes it via client, and returns the response plus the full
// response body bytes. The caller owns resp and must close resp.Body.
func PostSignedJSON(
	t testing.TB,
	client *http.Client,
	signer *crypto.RFC9421Signer,
	method, url string,
	body any,
) (*http.Response, []byte) {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("PostSignedJSON: marshal body: %v", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("PostSignedJSON: build request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if err := signer.Sign(req); err != nil {
		t.Fatalf("PostSignedJSON: sign request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PostSignedJSON: Do request: %v", err)
	}

	respBody, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()

	if readErr != nil {
		t.Fatalf("PostSignedJSON: read response body: %v", readErr)
	}

	if closeErr != nil {
		t.Fatalf("PostSignedJSON: close response body: %v", closeErr)
	}

	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	return resp, respBody
}

// PostSignedJSONStatusBody sends a signed JSON POST and returns the HTTP status
// and response body bytes. It closes the response body before returning.
func PostSignedJSONStatusBody(
	t testing.TB,
	client *http.Client,
	signer *crypto.RFC9421Signer,
	url string,
	body any,
) (status int, respBody []byte) {
	t.Helper()

	resp, respBody := PostSignedJSON(t, client, signer, http.MethodPost, url, body)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("PostSignedJSONStatusBody: close response body: %v", err)
	}

	return resp.StatusCode, respBody
}

// PostSignedJSONDecode sends a signed JSON POST, unmarshals a JSON response
// into out when out is non-nil and the body is non-empty, and returns the HTTP
// status plus the raw response body bytes.
func PostSignedJSONDecode(
	t testing.TB,
	client *http.Client,
	signer *crypto.RFC9421Signer,
	url string,
	body any,
	out any,
) (status int, respBody []byte) {
	t.Helper()

	status, respBody = PostSignedJSONStatusBody(t, client, signer, url, body)
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			t.Fatalf("PostSignedJSONDecode: unmarshal response: %v", err)
		}
	}

	return status, respBody
}
