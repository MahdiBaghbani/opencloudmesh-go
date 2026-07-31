// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package peertrust_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
)

func TestPolicyEngine_DenylistWins(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &peertrust.PolicyConfig{
		AllowList: []string{"example.com"},
		DenyList:  []string{"example.com"},
	}

	pe := peertrust.NewPolicyEngine(cfg, nil, logger)
	result := pe.Evaluate(context.Background(), "example.com", false)

	if result.Allowed {
		t.Error("expected denied: denylist should win over allowlist")
	}

	if result.ReasonCode != "denied_by_denylist" {
		t.Errorf("expected reason_code 'denied_by_denylist', got %q", result.ReasonCode)
	}
}

func TestPolicyEngine_AllowlistOverridesFederation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &peertrust.PolicyConfig{
		AllowList: []string{"trusted.example.com"},
		DenyList:  []string{},
	}

	pe := peertrust.NewPolicyEngine(cfg, nil, logger)
	result := pe.Evaluate(context.Background(), "trusted.example.com", false)

	if !result.Allowed {
		t.Error("expected allowed: host is in allowlist")
	}

	if result.ReasonCode != "allowed_by_allowlist" {
		t.Errorf("expected reason_code 'allowed_by_allowlist', got %q", result.ReasonCode)
	}
}

func TestPolicyEngine_DenylistEnforced(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &peertrust.PolicyConfig{
		DenyList: []string{"blocked.example.com"},
	}

	pe := peertrust.NewPolicyEngine(cfg, nil, logger)
	result := pe.Evaluate(context.Background(), "blocked.example.com", false)

	if result.Allowed {
		t.Error("expected denied: host is in denylist")
	}

	if result.ReasonCode != "denied_by_denylist" {
		t.Errorf("expected reason_code 'denied_by_denylist', got %q", result.ReasonCode)
	}
}

func TestPolicyEngine_CaseInsensitive(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &peertrust.PolicyConfig{
		AllowList: []string{"Example.COM"},
	}

	pe := peertrust.NewPolicyEngine(cfg, nil, logger)
	result := pe.Evaluate(context.Background(), "example.com", false)

	if !result.Allowed {
		t.Error("expected allowed: case-insensitive matching")
	}
}

func TestPolicyEngine_NotAllowed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &peertrust.PolicyConfig{
		AllowList: []string{},
		DenyList:  []string{},
	}

	pe := peertrust.NewPolicyEngine(cfg, nil, logger)
	result := pe.Evaluate(context.Background(), "unknown.example.com", false)

	if result.Allowed {
		t.Error("expected denied: host not in any list")
	}

	if result.ReasonCode != "not_allowed" {
		t.Errorf("expected reason_code 'not_allowed', got %q", result.ReasonCode)
	}
}
