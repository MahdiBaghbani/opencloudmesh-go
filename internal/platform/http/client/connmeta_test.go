// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func tlsTestClient() *httpclient.Client {
	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true

	return httpclient.New(cfg, nil)
}

func TestGetJSONWithConnMeta_CapturesServerIPAndTLS(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tshttp.MustWrite(t, w, []byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	client := tlsTestClient()

	//nolint:bodyclose // GetJSONWithConnMeta closes the body before returning
	body, resp, meta, err := client.GetJSONWithConnMeta(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("GetJSONWithConnMeta: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("expected body")
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	if resp.TLS == nil {
		t.Fatal("expected TLS state on HTTPS response")
	}

	if meta.ServerIP == "" {
		t.Fatal("expected connected server IP")
	}

	if meta.ServerIP != "127.0.0.1" && meta.ServerIP != "::1" {
		t.Fatalf("unexpected server IP %q", meta.ServerIP)
	}
}

func TestGetJSONWithConnMeta_PlainHTTPHasNoTLS(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Probe", "1")
		tshttp.MustWrite(t, w, []byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := tlsTestClient()

	//nolint:bodyclose // GetJSONWithConnMeta closes the body before returning
	_, resp, meta, err := client.GetJSONWithConnMeta(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("GetJSONWithConnMeta: %v", err)
	}

	if resp.TLS != nil {
		t.Fatal("expected nil TLS on plain HTTP")
	}

	if meta.ServerIP == "" {
		t.Fatal("expected connected server IP on plain HTTP")
	}
}

func TestGetWithConnMeta_ErrorPathDoesNotPanic(t *testing.T) {
	t.Parallel()

	client := httpclient.New(tshttp.PermissiveConfig(), nil)

	//nolint:bodyclose // no response on dial failure
	_, meta, err := client.GetWithConnMeta(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected connection error")
	}

	if meta.ServerIP != "" {
		t.Fatalf("expected empty server IP on failed dial, got %q", meta.ServerIP)
	}
}

func TestGetJSONWithConnMeta_ReusedConnectionStillCapturesIP(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tshttp.MustWrite(t, w, []byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := tlsTestClient()
	ctx := context.Background()

	//nolint:bodyclose // GetJSONWithConnMeta closes the body before returning
	_, _, firstMeta, err := client.GetJSONWithConnMeta(ctx, server.URL)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	//nolint:bodyclose // GetJSONWithConnMeta closes the body before returning
	_, _, secondMeta, err := client.GetJSONWithConnMeta(ctx, server.URL)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}

	if firstMeta.ServerIP == "" || secondMeta.ServerIP == "" {
		t.Fatal("expected server IP on reused connection")
	}

	if firstMeta.ServerIP != secondMeta.ServerIP {
		t.Fatalf("server IP mismatch: %q vs %q", firstMeta.ServerIP, secondMeta.ServerIP)
	}
}

func TestGetJSONWithConnMeta_PreservesHeadersBeforeBodyClose(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom", "probe")
		tshttp.MustWrite(t, w, []byte(`{}`))
	}))
	t.Cleanup(server.Close)

	client := tlsTestClient()

	//nolint:bodyclose // GetJSONWithConnMeta closes the body before returning
	_, resp, _, err := client.GetJSONWithConnMeta(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("GetJSONWithConnMeta: %v", err)
	}

	if resp.Header.Get("X-Custom") != "probe" {
		t.Fatalf("header = %q, want probe", resp.Header.Get("X-Custom"))
	}
}
