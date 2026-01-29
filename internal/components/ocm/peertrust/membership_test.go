package peertrust_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
)

func TestTrustGroupManager_IsMember(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create manager without DS client (no network calls), scheme=https
	m := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", logger, 10*time.Second)

	cfg := &peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
	}
	m.AddTrustGroup(cfg)

	// Set cache with directory listings (simulating a previous refresh)
	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member1.example.com", DisplayName: "Member 1"},
				{URL: "https://member2.example.com:9200", DisplayName: "Member 2"},
			},
		},
	}, time.Now())

	tests := []struct {
		host     string
		expected bool
	}{
		{"member1.example.com", true},
		{"member2.example.com:9200", true},
		{"unknown.example.com", false},
		{"MEMBER1.EXAMPLE.COM", true}, // case insensitive
		{"member1.example.com:443", true}, // default port stripping
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := m.IsMember(context.Background(), tt.host)
			if result != tt.expected {
				t.Errorf("IsMember(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestTrustGroupManager_DisabledTrustGroup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	m := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", logger, 10*time.Second)

	cfg := &peertrust.TrustGroupConfig{
		TrustGroupID: "disabled-tg",
		Enabled:      false,
	}
	m.AddTrustGroup(cfg)

	m.SetCacheForTesting("disabled-tg", []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member.example.com", DisplayName: "Member"},
			},
		},
	}, time.Now())

	if m.IsMember(context.Background(), "member.example.com") {
		t.Error("expected not a member: trust group is disabled")
	}
}

func TestTrustGroupManager_M1UnionAcrossTrustGroups(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	m := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", logger, 10*time.Second)

	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "tg1",
		Enabled:      true,
	})
	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "tg2",
		Enabled:      true,
	})

	m.SetCacheForTesting("tg1", []directoryservice.Listing{
		{
			Federation: "fed1",
			Servers: []directoryservice.Server{
				{URL: "https://member1.example.com", DisplayName: "Member 1"},
			},
		},
	}, time.Now())

	m.SetCacheForTesting("tg2", []directoryservice.Listing{
		{
			Federation: "fed2",
			Servers: []directoryservice.Server{
				{URL: "https://member2.example.com", DisplayName: "Member 2"},
			},
		},
	}, time.Now())

	// Both should be members (M1 union)
	if !m.IsMember(context.Background(), "member1.example.com") {
		t.Error("expected member1 to be a member")
	}
	if !m.IsMember(context.Background(), "member2.example.com") {
		t.Error("expected member2 to be a member")
	}
}
