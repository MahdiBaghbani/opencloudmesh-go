// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// TestBuild_RejectsCrossAuthorityJwksURIOverride confirms the same-authority
// check deferred from config.Load runs in wiring.Build and fails fast before
// services start, once the discovery endpoint authority is resolved.
func TestBuild_RejectsCrossAuthorityJwksURIOverride(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.JwksURI = "https://other.example.com/jwks.json"

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err == nil {
		t.Fatal("expected Build to fail for cross-authority signature.jwks_uri override")
	}

	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Fatalf("Build error = %v, want mention of signature.jwks_uri", err)
	}
}

// TestBuild_AcceptsSameAuthorityJwksURIOverride confirms a same-authority
// override passes the deferred wiring-level check.
func TestBuild_AcceptsSameAuthorityJwksURIOverride(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.JwksURI = cfg.PublicOrigin + "/custom/jwks.json"

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed for same-authority signature.jwks_uri override: %v", err)
	}

	if result.Deps == nil {
		t.Fatal("Build must return Deps")
	}
}

// TestBuild_EmptyJwksURIOverrideDoesNotFailBuild confirms the deferred check
// is a no-op when no override is configured.
func TestBuild_EmptyJwksURIOverrideDoesNotFailBuild(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed with empty signature.jwks_uri: %v", err)
	}

	if result.Deps == nil {
		t.Fatal("Build must return Deps")
	}
}
