// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package http_test

import (
	"os"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClearProxyEnv_ClearsDuringTest(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8443")
	t.Setenv("NO_PROXY", "localhost")
	t.Setenv("http_proxy", "http://lower.example:8080")
	t.Setenv("https_proxy", "http://lower.example:8443")
	t.Setenv("no_proxy", "127.0.0.1")

	tshttp.ClearProxyEnv(t)

	for _, key := range tshttp.ProxyEnvKeys {
		if _, ok := os.LookupEnv(key); ok {
			t.Fatalf("%s should be unset during test", key)
		}
	}
}

func TestClearProxyEnv_RestoresAfterCleanup(t *testing.T) {
	const value = "http://restore.example:3128"

	for _, key := range tshttp.ProxyEnvKeys {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)

			t.Run("cleared", func(t *testing.T) {
				tshttp.ClearProxyEnv(t)

				if _, ok := os.LookupEnv(key); ok {
					t.Fatalf("%s should be unset inside subtest", key)
				}
			})

			got, ok := os.LookupEnv(key)
			if !ok {
				t.Fatalf("%s should be restored after cleanup", key)
			}

			if got != value {
				t.Fatalf("%s = %q, want %q", key, got, value)
			}
		})
	}
}

func TestClearProxyEnv_KeepsUnsetAfterCleanup(t *testing.T) {
	for _, key := range tshttp.ProxyEnvKeys {
		t.Run(key, func(t *testing.T) {
			origVal, origSet := os.LookupEnv(key)

			t.Cleanup(func() {
				if origSet {
					_ = os.Setenv(key, origVal) //nolint:errcheck // test setup: environment variable
				} else {
					_ = os.Unsetenv(key) //nolint:errcheck // test setup: environment variable
				}
			})

			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset %s: %v", key, err)
			}

			t.Run("cleared", func(t *testing.T) {
				tshttp.ClearProxyEnv(t)

				if _, ok := os.LookupEnv(key); ok {
					t.Fatalf("%s should be unset inside subtest", key)
				}
			})

			if _, ok := os.LookupEnv(key); ok {
				t.Fatalf("%s should remain unset after cleanup", key)
			}
		})
	}
}
