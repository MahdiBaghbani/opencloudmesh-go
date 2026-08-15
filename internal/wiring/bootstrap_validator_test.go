// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

func TestBuildValidatorCore_LoadsSharedSalt(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.DataDir = t.TempDir()

	first, err := buildValidatorCore(cfg)
	if err != nil {
		t.Fatalf("first buildValidatorCore: %v", err)
	}

	if first == nil {
		t.Fatal("expected non-nil validator core")
	}

	salt := first.StatsSalt()
	if len(salt) != statistics.RedactionSaltSize {
		t.Fatalf("salt len = %d, want %d", len(salt), statistics.RedactionSaltSize)
	}

	second, err := buildValidatorCore(cfg)
	if err != nil {
		t.Fatalf("second buildValidatorCore: %v", err)
	}

	if got := second.StatsSalt(); string(got) != string(salt) {
		t.Fatal("expected stable shared salt across bootstrap wiring")
	}
}

func TestBuildValidatorCore_RejectsStatisticsDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.DataDir = t.TempDir()
	cfg.Statistics.Enabled = false

	if _, err := buildValidatorCore(cfg); err == nil {
		t.Fatal("expected error when statistics.enabled=false")
	}
}

func TestBuildRealIPExtractor_ValidatorUsesStrictTrustedProxies(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()

	tp, err := buildRealIPExtractor(cfg)
	if err != nil {
		t.Fatalf("buildRealIPExtractor: %v", err)
	}

	if !tp.IsTrusted(net.ParseIP("172.17.0.1")) {
		t.Error("expected docker bridge 172.17.0.1 to be trusted in validator mode")
	}
}

func TestBuildRealIPExtractor_ValidatorRejectsMalformedProxy(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Server.TrustedProxies = []string{"not-a-cidr"}

	if _, err := buildRealIPExtractor(cfg); err == nil {
		t.Fatal("expected error for malformed trusted proxy in validator mode")
	}
}

func TestBuildValidatorCore_RejectsUnreadableSalt(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.DataDir = t.TempDir()

	if err := writeUnreadableSaltDir(cfg.Persistence.DataDir); err != nil {
		t.Fatalf("prepare unreadable salt dir: %v", err)
	}

	if _, err := buildValidatorCore(cfg); err == nil {
		t.Fatal("expected error when salt file is unreadable")
	}
}

func writeUnreadableSaltDir(dir string) error {
	path := filepath.Join(dir, statistics.RedactionSaltFileName)
	salt := make([]byte, statistics.RedactionSaltSize)

	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return fmt.Errorf("write unreadable salt stub: %w", err)
	}

	if err := os.Chmod(path, 0o000); err != nil {
		return fmt.Errorf("chmod salt unreadable: %w", err)
	}

	return nil
}
