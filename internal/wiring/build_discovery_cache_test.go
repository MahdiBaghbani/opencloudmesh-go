// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestDiscoveryCacheSkip_WiresClient(t *testing.T) {
	t.Run("SkipDiscoveryCache=true wires NoopCache to discovery client", func(t *testing.T) {
		result, err := wiring.Build(
			config.DevConfig(),
			tslog.DiscardLogger(),
			harnessBuildOpts(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		d := result.Deps
		if !d.DiscoveryClient.IsNoopCache() {
			t.Error("expected NoopCache when SkipDiscoveryCache=true, got a different cache")
		}

		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil even when SkipDiscoveryCache=true")
		}
	})

	t.Run("SkipDiscoveryCache=false wires discovery LRU-capped cache and ratelimit TTL-only cache", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipDiscoveryCache = false

		result, err := wiring.Build(
			config.DevConfig(),
			tslog.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		d := result.Deps
		if d.DiscoveryClient.IsNoopCache() {
			t.Error("discovery client must not use NoopCache when SkipDiscoveryCache=false")
		}

		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil when SkipDiscoveryCache=false")
		}
	})
}

func TestBuild_DiscoveryCacheLRUCappedAndRatelimitTTLOnly(t *testing.T) {
	opts := harnessBuildOpts()
	opts.SkipDiscoveryCache = false

	result, err := wiring.Build(
		config.DevConfig(),
		tslog.DiscardLogger(),
		opts,
	)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	discoveryCache, ok := result.Deps.DiscoveryClient.Cache().(*memory.Cache)
	if !ok {
		t.Fatalf("discovery cache type = %T, want *memory.Cache", result.Deps.DiscoveryClient.Cache())
	}

	ratelimitCache, ok := result.Deps.Cache.(*memory.Cache)
	if !ok {
		t.Fatalf("ratelimit cache type = %T, want *memory.Cache", result.Deps.Cache)
	}

	if discoveryCache == ratelimitCache {
		t.Fatal("discovery and ratelimit must be distinct cache instances")
	}

	ctx := context.Background()
	ttl := time.Minute

	for i := 0; i <= memory.DefaultMaxEntries; i++ {
		key := fmt.Sprintf("discovery-%d", i)
		if setErr := discoveryCache.Set(ctx, key, []byte(key), ttl); setErr != nil {
			t.Fatalf("discovery Set %s: %v", key, setErr)
		}
	}

	if _, getErr := discoveryCache.Get(ctx, "discovery-0"); !errors.Is(getErr, cache.ErrNotFound) {
		t.Fatalf(
			"discovery Get discovery-0 = %v, want ErrNotFound (LRU-capped at memory.DefaultMaxEntries=%d)",
			getErr,
			memory.DefaultMaxEntries,
		)
	}

	for i := 0; i <= memory.DefaultMaxEntries; i++ {
		key := fmt.Sprintf("ratelimit-%d", i)
		if setErr := ratelimitCache.Set(ctx, key, []byte(key), ttl); setErr != nil {
			t.Fatalf("ratelimit Set %s: %v", key, setErr)
		}
	}

	val, getErr := ratelimitCache.Get(ctx, "ratelimit-0")
	if getErr != nil {
		t.Fatalf("ratelimit Get ratelimit-0: %v, want present (TTL-only, no LRU eviction)", getErr)
	}

	if string(val) != "ratelimit-0" {
		t.Fatalf("ratelimit-0 = %q, want %q", val, "ratelimit-0")
	}
}
