package federation_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
)

func TestFederationManager_IsMember(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create manager without DS client (no network calls)
	fm := federation.NewFederationManager(federation.DefaultCacheConfig(), nil, logger, 10*time.Second)

	// Add a federation with pre-populated cache
	cfg := &federation.FederationConfig{
		FederationID: "test-fed",
		Enabled:      true,
	}
	fm.AddFederation(cfg)

	// Directly set cache (simulating a previous refresh)
	fm.SetCacheForTesting("test-fed", &federation.MembershipCache{
		FederationID: "test-fed",
		LastRefresh:  time.Now(),
		Members: []federation.Member{
			{Host: "member1.example.com"},
			{Host: "member2.example.com:9200"},
		},
	})

	// Test membership
	tests := []struct {
		host     string
		expected bool
	}{
		{"member1.example.com", true},
		{"member2.example.com:9200", true},
		{"member2.example.com:9200", true},
		{"unknown.example.com", false},
		{"MEMBER1.EXAMPLE.COM", true}, // Case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := fm.IsMember(context.Background(), tt.host)
			if result != tt.expected {
				t.Errorf("IsMember(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestFederationManager_DisabledFederation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	fm := federation.NewFederationManager(federation.DefaultCacheConfig(), nil, logger, 10*time.Second)

	// Add a disabled federation
	cfg := &federation.FederationConfig{
		FederationID: "disabled-fed",
		Enabled:      false,
	}
	fm.AddFederation(cfg)

	fm.SetCacheForTesting("disabled-fed", &federation.MembershipCache{
		FederationID: "disabled-fed",
		LastRefresh:  time.Now(),
		Members: []federation.Member{
			{Host: "member.example.com"},
		},
	})

	// Should not be a member because federation is disabled
	if fm.IsMember(context.Background(), "member.example.com") {
		t.Error("expected not a member: federation is disabled")
	}
}

func TestFederationManager_M1UnionAcrossFederations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	fm := federation.NewFederationManager(federation.DefaultCacheConfig(), nil, logger, 10*time.Second)

	// Add two federations
	fm.AddFederation(&federation.FederationConfig{
		FederationID: "fed1",
		Enabled:      true,
	})
	fm.AddFederation(&federation.FederationConfig{
		FederationID: "fed2",
		Enabled:      true,
	})

	fm.SetCacheForTesting("fed1", &federation.MembershipCache{
		FederationID: "fed1",
		LastRefresh:  time.Now(),
		Members: []federation.Member{
			{Host: "member1.example.com"},
		},
	})
	fm.SetCacheForTesting("fed2", &federation.MembershipCache{
		FederationID: "fed2",
		LastRefresh:  time.Now(),
		Members: []federation.Member{
			{Host: "member2.example.com"},
		},
	})

	// Both should be members (M1 union)
	if !fm.IsMember(context.Background(), "member1.example.com") {
		t.Error("expected member1 to be a member")
	}
	if !fm.IsMember(context.Background(), "member2.example.com") {
		t.Error("expected member2 to be a member")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		host     string
		scheme   string
		expected string
	}{
		{"EXAMPLE.COM", "https", "example.com"},
		{"example.com:443", "https", "example.com"},
		{"example.com:80", "http", "example.com"},
		{"example.com:9200", "https", "example.com:9200"},
		{"example.com:9200", "http", "example.com:9200"},
	}

	for _, tt := range tests {
		t.Run(tt.host+"/"+tt.scheme, func(t *testing.T) {
			result := federation.NormalizeHost(tt.host, tt.scheme)
			if result != tt.expected {
				t.Errorf("NormalizeHost(%q, %q) = %q, want %q",
					tt.host, tt.scheme, result, tt.expected)
			}
		})
	}
}
