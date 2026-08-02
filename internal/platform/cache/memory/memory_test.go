// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestCache_SetGet(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	// Set a value
	err := c.Set(ctx, "key1", []byte("value1"), time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get the value
	val, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(val) != "value1" {
		t.Errorf("expected 'value1', got %q", string(val))
	}
}

func TestCache_GetNotFound(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	_, err := c.Get(ctx, "nonexistent")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCache_Expiration(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	// Set with very short TTL
	err := c.Set(ctx, "key1", []byte("value1"), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should exist initially
	exists, err := c.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}

	if !exists {
		t.Error("key should exist initially")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be expired now
	_, err = c.Get(ctx, "key1")
	if !errors.Is(err, cache.ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}

	exists, err = c.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}

	if exists {
		t.Error("expired key should not exist")
	}
}

func TestCache_Delete(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	if err := c.Set(ctx, "key1", []byte("value1"), time.Minute); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if err := c.Delete(ctx, "key1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err := c.Get(ctx, "key1")
	if !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestCache_ValueIsolation(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	original := []byte("original")
	if err := c.Set(ctx, "key1", original, time.Minute); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Modify original
	original[0] = 'X'

	// Cached value should be unchanged
	val, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(val) != "original" {
		t.Errorf("cache value was mutated: %q", string(val))
	}

	// Modify returned value
	val[0] = 'Y'

	// Cached value should still be unchanged
	val2, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(val2) != "original" {
		t.Errorf("cache value was mutated via returned slice: %q", string(val2))
	}
}

func TestCounter_Increment(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	// First increment creates counter
	count, resetAt, err := c.Increment(ctx, "counter1", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
	// resetAt should be approximately 1 minute from now
	expectedReset := time.Now().Add(time.Minute)
	if resetAt.Before(expectedReset.Add(-time.Second)) || resetAt.After(expectedReset.Add(time.Second)) {
		t.Errorf("resetAt %v not within expected range around %v", resetAt, expectedReset)
	}

	// Second increment adds to it (same window, same resetAt)
	count, resetAt2, err := c.Increment(ctx, "counter1", 5, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	if count != 6 {
		t.Errorf("expected 6, got %d", count)
	}
	// resetAt should be unchanged (same window)
	if resetAt2.Sub(resetAt) > time.Second {
		t.Errorf("resetAt changed unexpectedly: was %v, now %v", resetAt, resetAt2)
	}

	// GetCount should return same value
	count, err = c.GetCount(ctx, "counter1")
	if err != nil {
		t.Fatalf("GetCount failed: %v", err)
	}

	if count != 6 {
		t.Errorf("expected 6, got %d", count)
	}
}

func TestCounter_Expiration(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	// Create counter with short TTL
	_, _, err := c.Increment(ctx, "counter1", 10, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Counter should be reset
	count, err := c.GetCount(ctx, "counter1")
	if err != nil {
		t.Fatalf("GetCount failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 after expiration, got %d", count)
	}

	// New increment should start fresh
	count, _, err = c.Increment(ctx, "counter1", 1, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 after expired increment, got %d", count)
	}
}

func TestCounter_Reset(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	_, _, err := c.Increment(ctx, "counter1", 100, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	if cerr := c.Reset(ctx, "counter1"); cerr != nil {
		t.Fatalf("Reset failed: %v", cerr)
	}

	count, err := c.GetCount(ctx, "counter1")
	if err != nil {
		t.Fatalf("GetCount failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
}

func TestCounter_ResetAt(t *testing.T) {
	c := memory.New(time.Minute, 0)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	ttl := 30 * time.Second
	now := time.Now()

	// First increment establishes the window
	count, resetAt, err := c.Increment(ctx, "counter_resetat", 1, ttl)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// resetAt should be approximately ttl from now
	expectedReset := now.Add(ttl)
	if resetAt.Before(expectedReset.Add(-2*time.Second)) || resetAt.After(expectedReset.Add(2*time.Second)) {
		t.Errorf("resetAt %v not within 2s of expected %v", resetAt, expectedReset)
	}

	// Subsequent increments should return the same resetAt (within the same window)
	time.Sleep(10 * time.Millisecond)

	_, resetAt2, err := c.Increment(ctx, "counter_resetat", 1, ttl)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	// resetAt2 should be close to original resetAt (not reset)
	diff := resetAt2.Sub(resetAt)
	if diff < 0 {
		diff = -diff
	}

	if diff > time.Second {
		t.Errorf("resetAt changed unexpectedly: first %v, second %v (diff: %v)", resetAt, resetAt2, diff)
	}
}

func TestCache_CleanupLoop(t *testing.T) {
	// Create cache with fast cleanup
	c := memory.New(time.Minute, 50*time.Millisecond)
	defer tshttp.MustClose(t, c)

	ctx := context.Background()

	// Set items that will expire quickly
	if err := c.Set(ctx, "expire1", []byte("v1"), 10*time.Millisecond); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if err := c.Set(ctx, "expire2", []byte("v2"), 10*time.Millisecond); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	if err := c.Set(ctx, "keep", []byte("v3"), time.Minute); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Expired items should be gone, keep should remain
	exists, err := c.Exists(ctx, "keep")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}

	if !exists {
		t.Error("'keep' should still exist")
	}
}
