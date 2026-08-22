// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestGradeDiscovery_FailWarnPass(t *testing.T) {
	t.Parallel()

	failErr := errors.New("fetch failed")

	cases := []struct {
		name   string
		result *discovery.FetchResult
		err    error
		want   string
	}{
		{name: "nil result", want: validatorcore.GradeFail},
		{name: "fetch error", result: &discovery.FetchResult{FetchErr: failErr}, err: failErr, want: validatorcore.GradeFail},
		{
			name: "warnings",
			result: &discovery.FetchResult{
				Discovery: &spec.Discovery{Enabled: true, Warnings: []string{"compat"}},
			},
			want: validatorcore.GradeWarn,
		},
		{
			name: "ok",
			result: &discovery.FetchResult{
				Discovery: &spec.Discovery{Enabled: true, APIVersion: "1.4.0"},
			},
			want: validatorcore.GradePass,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := GradeDiscovery(tc.result, tc.err)
			if got == nil || *got != tc.want {
				t.Fatalf("GradeDiscovery = %v, want %q", got, tc.want)
			}
		})
	}
}

func TestAdvertisedJWKS_EmptyURIPolicy(t *testing.T) {
	t.Parallel()

	uri, advertised := advertisedJWKS(nil)
	if advertised || uri != "" {
		t.Fatalf("nil discovery advertised=%v uri=%q", advertised, uri)
	}

	_, advertised = advertisedJWKS(&spec.Discovery{})
	if advertised {
		t.Fatal("no uri and no http-sig must not count as advertised")
	}

	uri, advertised = advertisedJWKS(&spec.Discovery{Capabilities: []string{spec.CapabilityHTTPSig}})
	if !advertised || uri != "" {
		t.Fatalf("http-sig without uri advertised=%v uri=%q", advertised, uri)
	}

	uri, advertised = advertisedJWKS(&spec.Discovery{JwksUri: " https://peer.example/jwks "})
	if !advertised || uri != "https://peer.example/jwks" {
		t.Fatalf("explicit uri advertised=%v uri=%q", advertised, uri)
	}
}

func probeSourceFiles(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	var b strings.Builder

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}

		if !strings.HasPrefix(name, "probe") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		raw, readErr := os.ReadFile(filepath.Clean(name))
		if readErr != nil {
			t.Fatalf("ReadFile %s: %v", name, readErr)
		}

		if _, writeErr := b.Write(raw); writeErr != nil {
			t.Fatalf("write %s: %v", name, writeErr)
		}

		if writeErr := b.WriteByte('\n'); writeErr != nil {
			t.Fatalf("write newline %s: %v", name, writeErr)
		}
	}

	return b.String()
}
