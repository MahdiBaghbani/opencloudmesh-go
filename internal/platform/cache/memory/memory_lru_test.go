// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memory_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestCache_LRUEvictsOldestBeyondCap(t *testing.T) {
	c := memory.NewBounded(time.Minute, 0, 2)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	set := func(key string) {
		if err := c.Set(ctx, key, []byte(key), time.Minute); err != nil {
			t.Fatalf("Set %s: %v", key, err)
		}
	}

	set("k1")
	set("k2")

	// Touch k1 so k2 becomes the least recently used entry.
	if _, err := c.Get(ctx, "k1"); err != nil {
		t.Fatalf("Get k1: %v", err)
	}

	set("k3")

	if _, err := c.Get(ctx, "k2"); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Get k2 = %v, want ErrNotFound (evicted as least recently used)", err)
	}

	for _, key := range []string{"k1", "k3"} {
		if _, err := c.Get(ctx, key); err != nil {
			t.Fatalf("Get %s: %v, want present", key, err)
		}
	}
}

func TestCache_UnboundedInstanceDoesNotEvict(t *testing.T) {
	// The rate-limit cache instance is TTL-only: inserts beyond the discovery
	// cardinality default must not evict anything.
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	for i := 0; i <= memory.DefaultMaxEntries; i++ {
		key := fmt.Sprintf("key-%d", i)
		if err := c.Set(ctx, key, []byte(key), time.Minute); err != nil {
			t.Fatalf("Set %s: %v", key, err)
		}
	}

	val, err := c.Get(ctx, "key-0")
	if err != nil {
		t.Fatalf("Get key-0 after over-cap inserts: %v, want present (no LRU eviction)", err)
	}

	if string(val) != "key-0" {
		t.Fatalf("key-0 = %q, want %q", val, "key-0")
	}
}

func TestCache_ExpiredGetDoesNotPromoteLRU(t *testing.T) {
	// An expired read must delete without refreshing recency. Otherwise a
	// polled stale key stays hot and protects itself from LRU eviction.
	c := memory.NewBounded(time.Minute, 0, 2)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	if err := c.Set(ctx, "keep", []byte("keep"), time.Minute); err != nil {
		t.Fatalf("Set keep: %v", err)
	}

	if err := c.Set(ctx, "stale", []byte("stale"), 10*time.Millisecond); err != nil {
		t.Fatalf("Set stale: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	if _, err := c.Get(ctx, "stale"); !errors.Is(err, cache.ErrExpired) {
		t.Fatalf("Get stale = %v, want ErrExpired", err)
	}

	if err := c.Set(ctx, "fresh", []byte("fresh"), time.Minute); err != nil {
		t.Fatalf("Set fresh: %v", err)
	}

	if _, err := c.Get(ctx, "keep"); err != nil {
		t.Fatalf("Get keep after expired read: %v, want present (stale must not have been promoted)", err)
	}

	if _, err := c.Get(ctx, "stale"); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Get stale after expiry delete = %v, want ErrNotFound", err)
	}
}

func TestCache_ExpiredExistsDoesNotPromoteLRU(t *testing.T) {
	c := memory.NewBounded(time.Minute, 0, 2)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	if err := c.Set(ctx, "keep", []byte("keep"), time.Minute); err != nil {
		t.Fatalf("Set keep: %v", err)
	}

	if err := c.Set(ctx, "stale", []byte("stale"), 10*time.Millisecond); err != nil {
		t.Fatalf("Set stale: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	exists, err := c.Exists(ctx, "stale")
	if err != nil {
		t.Fatalf("Exists stale: %v", err)
	}

	if exists {
		t.Fatal("Exists stale = true, want false")
	}

	if err := c.Set(ctx, "fresh", []byte("fresh"), time.Minute); err != nil {
		t.Fatalf("Set fresh: %v", err)
	}

	if _, err := c.Get(ctx, "keep"); err != nil {
		t.Fatalf("Get keep after expired Exists: %v, want present (stale must not have been promoted)", err)
	}
}

func TestCounter_NeverLRUBounded(t *testing.T) {
	// Counters expire by TTL only, even on an LRU-bounded instance: evicting
	// a live rate-limit window would reset its count and bypass the limit.
	c := memory.NewBounded(time.Minute, 0, 2)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	keys := []string{"ratelimit:a", "ratelimit:b", "ratelimit:c", "ratelimit:d"}
	for _, key := range keys {
		count, _, err := c.Increment(ctx, key, 1, time.Minute)
		if err != nil {
			t.Fatalf("Increment %s: %v", key, err)
		}

		if count != 1 {
			t.Fatalf("Increment %s = %d, want 1", key, count)
		}
	}

	for _, key := range keys {
		count, err := c.GetCount(ctx, key)
		if err != nil {
			t.Fatalf("GetCount %s: %v", key, err)
		}

		if count != 1 {
			t.Fatalf("GetCount %s = %d, want 1 (no eviction)", key, count)
		}
	}
}
