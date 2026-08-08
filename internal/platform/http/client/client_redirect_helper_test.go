// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func runSameHostRelativeRedirectTest(
	t *testing.T,
	targetBody string,
	getFailMsg string,
	requestCountFailMsg string,
) {
	t.Helper()

	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)

			return
		}

		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)

			if _, err := w.Write([]byte(targetBody)); err != nil {
				t.Errorf("write response: %v", err)
			}

			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), server.URL+"/start") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("%s: %v", getFailMsg, err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("%s, got %d", requestCountFailMsg, requestCount)
	}
}

func runCrossHostRedirectBlockedTest(t *testing.T, failMsg string) {
	t.Helper()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer targetServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL+"/target", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), redirectServer.URL+"/start") //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if err == nil {
		t.Fatal(failMsg)
	}

	if !strings.Contains(err.Error(), "different host") {
		t.Errorf("expected 'different host' in error, got: %v", err)
	}
}
