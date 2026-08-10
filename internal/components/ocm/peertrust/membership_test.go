// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package peertrust_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestTrustGroupManager_IsMember(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create manager without directory service client (no network calls), scheme=https
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
		{"MEMBER1.EXAMPLE.COM", true},     // case insensitive
		{"member1.example.com:443", true}, // default port stripping
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			t.Parallel()

			result := m.IsMember(context.Background(), tt.host, false)
			if result != tt.expected {
				t.Errorf("IsMember(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestTrustGroupManager_DisabledTrustGroup(t *testing.T) {
	t.Parallel()

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

	if m.IsMember(context.Background(), "member.example.com", false) {
		t.Error("expected not a member: trust group is disabled")
	}
}

func TestTrustGroupManager_M1UnionAcrossTrustGroups(t *testing.T) {
	t.Parallel()

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

	// Both should be members (union across trust groups)
	if !m.IsMember(context.Background(), "member1.example.com", false) {
		t.Error("expected member1 to be a member")
	}

	if !m.IsMember(context.Background(), "member2.example.com", false) {
		t.Error("expected member2 to be a member")
	}
}

func TestTrustGroupManager_IsMember_RequireVerified(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	m := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", logger, 10*time.Second)

	cfg := &peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
	}
	m.AddTrustGroup(cfg)

	// Mixed verified/unverified listings.
	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "verified-fed",
			Servers: []directoryservice.Server{
				{URL: "https://verified.example.com", DisplayName: "Verified"},
			},
			Verified: true,
		},
		{
			Federation: "unverified-fed",
			Servers: []directoryservice.Server{
				{URL: "https://unverified.example.com", DisplayName: "Unverified"},
			},
			Verified: false,
		},
	}, time.Now())

	// Without requireVerified, both are members.
	if !m.IsMember(context.Background(), "verified.example.com", false) {
		t.Error("expected verified.example.com to be a member with requireVerified=false")
	}

	if !m.IsMember(context.Background(), "unverified.example.com", false) {
		t.Error("expected unverified.example.com to be a member with requireVerified=false")
	}

	// With requireVerified, only verified is a member.
	if !m.IsMember(context.Background(), "verified.example.com", true) {
		t.Error("expected verified.example.com to be a member with requireVerified=true")
	}

	if m.IsMember(context.Background(), "unverified.example.com", true) {
		t.Error("expected unverified.example.com to NOT be a member with requireVerified=true")
	}
}

func TestTrustGroupManager_IsMember_MaxStaleDenies(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cacheConfig := peertrust.CacheConfig{
		TTL:      1 * time.Hour,
		MaxStale: 2 * time.Hour,
	}
	m := peertrust.NewTrustGroupManager(cacheConfig, nil, "https", logger, 10*time.Second)

	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
	})

	staleRefresh := time.Now().Add(-3 * time.Hour)
	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member.example.com", DisplayName: "Member"},
			},
			Verified: true,
		},
	}, staleRefresh)

	if m.IsMember(context.Background(), "member.example.com", false) {
		t.Error("expected not a member when cache age exceeds MaxStale")
	}
}

func TestTrustGroupManager_IsMember_WithinMaxStaleAllowsMember(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cacheConfig := peertrust.CacheConfig{
		TTL:      1 * time.Hour,
		MaxStale: 2 * time.Hour,
	}
	m := peertrust.NewTrustGroupManager(cacheConfig, nil, "https", logger, 10*time.Second)

	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
	})

	freshRefresh := time.Now().Add(-90 * time.Minute)
	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member.example.com", DisplayName: "Member"},
			},
			Verified: true,
		},
	}, freshRefresh)

	if !m.IsMember(context.Background(), "member.example.com", false) {
		t.Error("expected member when cache age is within MaxStale")
	}
}

func TestTrustGroupManager_IsMember_TTLVersusMaxStaleBoundary(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	cacheConfig := peertrust.CacheConfig{
		TTL:      30 * time.Minute,
		MaxStale: 2 * time.Hour,
	}
	m := peertrust.NewTrustGroupManager(cacheConfig, nil, "https", logger, 10*time.Second)

	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
	})

	listings := []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member.example.com", DisplayName: "Member"},
			},
			Verified: true,
		},
	}

	betweenAge := time.Now().Add(-45 * time.Minute)
	m.SetCacheForTesting("test-tg", listings, betweenAge)

	if !m.IsMember(context.Background(), "member.example.com", false) {
		t.Error("expected member between TTL and MaxStale")
	}

	beyondMaxStale := time.Now().Add(-3 * time.Hour)
	m.SetCacheForTesting("test-tg", listings, beyondMaxStale)

	if m.IsMember(context.Background(), "member.example.com", false) {
		t.Error("expected not a member beyond MaxStale")
	}
}

func TestTrustGroupManager_IsMember_MaxStaleTriggersRefresh(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	var fetchCount atomic.Int32

	var signalFetchStarted sync.Once

	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	refreshDone := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		signalFetchStarted.Do(func() { close(fetchStarted) })
		<-releaseFetch
		w.WriteHeader(http.StatusInternalServerError)
		close(refreshDone)
	}))
	defer ts.Close()

	dirClient := directoryservice.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), "required", logger)
	cacheConfig := peertrust.CacheConfig{
		TTL:      30 * time.Minute,
		MaxStale: 2 * time.Hour,
	}
	m := peertrust.NewTrustGroupManager(cacheConfig, dirClient, "https", logger, 10*time.Second)
	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID: "test-tg",
		Enabled:      true,
		DirectoryServices: []directoryservice.EndpointConfig{
			{URL: ts.URL, Enabled: true, Verification: "required"},
		},
	})

	staleRefresh := time.Now().Add(-3 * time.Hour)
	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "test",
			Servers: []directoryservice.Server{
				{URL: "https://member.example.com", DisplayName: "Member"},
			},
			Verified: true,
		},
	}, staleRefresh)

	const workers = 20

	workerReturned := make(chan struct{}, workers)

	// One stale IsMember starts the refresh; block its HTTP fetch until overlap is set up.
	go func() {
		_ = m.IsMember(context.Background(), "member.example.com", false)

		workerReturned <- struct{}{}
	}()

	select {
	case <-fetchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for directory service fetch to start")
	}

	for range workers - 1 {
		go func() {
			_ = m.IsMember(context.Background(), "member.example.com", false)

			workerReturned <- struct{}{}
		}()
	}

	for range workers {
		select {
		case <-workerReturned:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for worker IsMember to return")
		}
	}

	close(releaseFetch)

	select {
	case <-refreshDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for refresh to finish")
	}

	if got := fetchCount.Load(); got != 1 {
		t.Errorf("expected exactly one directory service fetch, got %d", got)
	}
}

func TestTrustGroupManager_MembershipRequiresVerifiedListings(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	m := peertrust.NewTrustGroupManager(peertrust.DefaultCacheConfig(), nil, "https", logger, 10*time.Second)
	m.AddTrustGroup(&peertrust.TrustGroupConfig{
		TrustGroupID:      "test-tg",
		Enabled:           true,
		EnforceMembership: true,
	})

	m.SetCacheForTesting("test-tg", []directoryservice.Listing{
		{
			Federation: "unverified-fed",
			Servers: []directoryservice.Server{
				{URL: "https://unverified.example.com", DisplayName: "Unverified"},
			},
			Verified: false,
		},
	}, time.Now())

	if m.IsMember(context.Background(), "unverified.example.com", true) {
		t.Error("expected unverified directory listing to be ignored for membership")
	}
}
