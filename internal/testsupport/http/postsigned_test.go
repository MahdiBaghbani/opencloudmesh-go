package http_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tscrypto "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPostSignedJSON_SignsAndRoundTripsBody(t *testing.T) {
	var (
		gotMethod      string
		gotContentType string
		gotSignature   string
		gotBody        []byte
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotSignature = r.Header.Get("Signature")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			http.Error(w, "read failed", http.StatusInternalServerError)

			return
		}

		gotBody = body

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"echo":true}`))
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	reqBody := map[string]string{"token": "abc"}

	resp, respBody := tshttp.PostSignedJSON(
		t,
		server.Client(),
		signer,
		http.MethodPost,
		server.URL+"/ocm/shares",
		reqBody,
	)
	defer resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}

	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}

	if gotSignature == "" {
		t.Fatal("expected Signature header on signed request")
	}

	wantBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal expected body: %v", err)
	}

	if string(gotBody) != string(wantBody) {
		t.Fatalf("request body = %q, want %q", gotBody, wantBody)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	if string(respBody) != `{"echo":true}` {
		t.Fatalf("response body = %q, want %q", respBody, `{"echo":true}`)
	}
}

func TestPostSignedJSON_ResponseBodyReadable(t *testing.T) {
	const wantBody = `{"echo":true}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wantBody))
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	resp, respBody := tshttp.PostSignedJSON(
		t,
		server.Client(),
		signer,
		http.MethodPost,
		server.URL,
		map[string]string{"ping": "pong"},
	)
	defer resp.Body.Close()

	fromBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read resp.Body: %v", err)
	}

	if string(fromBody) != string(respBody) {
		t.Fatalf("resp.Body = %q, want %q from returned bytes", fromBody, respBody)
	}

	if string(respBody) != wantBody {
		t.Fatalf("returned body = %q, want %q", respBody, wantBody)
	}
}

func TestPostSignedJSON_ReplayableWithSameBody(t *testing.T) {
	var callCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	reqBody := map[string]string{"token": "reuse-me"}

	wantBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal expected body: %v", err)
	}

	client := server.Client()

	resp1, respBody1 := tshttp.PostSignedJSON(
		t,
		client,
		signer,
		http.MethodPost,
		server.URL,
		reqBody,
	)
	defer resp1.Body.Close()

	resp2, respBody2 := tshttp.PostSignedJSON(
		t,
		client,
		signer,
		http.MethodPost,
		server.URL,
		reqBody,
	)
	defer resp2.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want %d", resp1.StatusCode, http.StatusOK)
	}

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}

	if string(respBody1) != string(wantBody) {
		t.Fatalf("first response body = %q, want %q", respBody1, wantBody)
	}

	if string(respBody2) != string(wantBody) {
		t.Fatalf("second response body = %q, want %q", respBody2, wantBody)
	}

	if callCount != 2 {
		t.Fatalf("server call count = %d, want 2", callCount)
	}
}

func TestPostSignedJSONStatusBody_ReturnsStatusAndBody(t *testing.T) {
	const wantBody = `{"received":true}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(wantBody))
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	status, respBody := tshttp.PostSignedJSONStatusBody(
		t,
		server.Client(),
		signer,
		server.URL,
		map[string]string{"ping": "pong"},
	)

	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", status, http.StatusAccepted)
	}

	if string(respBody) != wantBody {
		t.Fatalf("response body = %q, want %q", respBody, wantBody)
	}
}

func TestPostSignedJSONDecode_UnmarshalsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	var decoded map[string]bool

	status, raw := tshttp.PostSignedJSONDecode(
		t,
		server.Client(),
		signer,
		server.URL,
		map[string]string{"grant_type": "authorization_code"},
		&decoded,
	)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}

	if !decoded["ok"] {
		t.Fatalf("decoded = %#v, want ok=true", decoded)
	}

	if string(raw) != `{"ok":true}` {
		t.Fatalf("raw body = %q, want %q", raw, `{"ok":true}`)
	}
}

func TestPostSignedJSONDecode_NilOutDoesNotPanic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	status, raw := tshttp.PostSignedJSONDecode(
		t,
		server.Client(),
		signer,
		server.URL,
		map[string]string{"grant_type": "authorization_code"},
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}

	if string(raw) != `{"ok":true}` {
		t.Fatalf("raw body = %q, want %q", raw, `{"ok":true}`)
	}
}

func TestPostSignedJSONDecode_EmptyBodyDoesNotPanic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	km := tscrypto.MustTestKeyManager(t, server.URL)
	signer := crypto.NewRFC9421Signer(km)

	var decoded map[string]bool

	status, raw := tshttp.PostSignedJSONDecode(
		t,
		server.Client(),
		signer,
		server.URL,
		map[string]string{"grant_type": "authorization_code"},
		&decoded,
	)
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", status, http.StatusNoContent)
	}

	if len(raw) != 0 {
		t.Fatalf("raw body = %q, want empty", raw)
	}
}
