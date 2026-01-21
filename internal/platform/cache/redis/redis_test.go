package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/redis"
)

func TestNew_FailFastUnreachable(t *testing.T) {
	// Test that New() fails fast when Redis is unreachable
	cfg := &redis.Config{
		Addr:        "localhost:59999", // Unlikely to have Redis running here
		DialTimeout: 100 * time.Millisecond,
	}

	_, err := redis.New(cfg)
	if err == nil {
		t.Fatal("expected error when connecting to unreachable Redis, got nil")
	}

	// Error should mention connection or health check failure
	t.Logf("Got expected error: %v", err)
}

func TestDefaultConfig(t *testing.T) {
	cfg := redis.DefaultConfig()

	if cfg.Addr != "localhost:6379" {
		t.Errorf("expected default addr localhost:6379, got %s", cfg.Addr)
	}
	if cfg.DB != 0 {
		t.Errorf("expected default DB 0, got %d", cfg.DB)
	}
	if cfg.Password != "" {
		t.Errorf("expected empty default password, got %s", cfg.Password)
	}
}

func TestIncrement_ResetAt(t *testing.T) {
	// Start miniredis server
	s := miniredis.RunT(t)

	cfg := &redis.Config{
		Addr:        s.Addr(),
		DialTimeout: time.Second,
	}

	c, err := redis.New(cfg)
	if err != nil {
		t.Fatalf("failed to create redis cache: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	ttl := 30 * time.Second
	now := time.Now()

	// First increment establishes the window
	count, resetAt, err := c.Increment(ctx, "test_counter", 1, ttl)
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

	// Second increment should preserve the same window
	count2, resetAt2, err := c.Increment(ctx, "test_counter", 1, ttl)
	if err != nil {
		t.Fatalf("second Increment failed: %v", err)
	}
	if count2 != 2 {
		t.Errorf("expected count 2, got %d", count2)
	}

	// resetAt2 should be close to original resetAt (same window, TTL not reset)
	diff := resetAt2.Sub(resetAt)
	if diff < 0 {
		diff = -diff
	}
	if diff > 2*time.Second {
		t.Errorf("resetAt changed unexpectedly: first %v, second %v (diff: %v)", resetAt, resetAt2, diff)
	}
}

func TestIncrement_CounterValue(t *testing.T) {
	s := miniredis.RunT(t)

	cfg := &redis.Config{
		Addr:        s.Addr(),
		DialTimeout: time.Second,
	}

	c, err := redis.New(cfg)
	if err != nil {
		t.Fatalf("failed to create redis cache: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Multiple increments
	for i := 1; i <= 5; i++ {
		count, _, err := c.Increment(ctx, "counter", 1, time.Minute)
		if err != nil {
			t.Fatalf("Increment %d failed: %v", i, err)
		}
		if count != int64(i) {
			t.Errorf("expected count %d, got %d", i, count)
		}
	}

	// GetCount should match
	count, err := c.GetCount(ctx, "counter")
	if err != nil {
		t.Fatalf("GetCount failed: %v", err)
	}
	if count != 5 {
		t.Errorf("expected GetCount 5, got %d", count)
	}
}

func TestSetGetDelete(t *testing.T) {
	s := miniredis.RunT(t)

	cfg := &redis.Config{
		Addr:        s.Addr(),
		DialTimeout: time.Second,
	}

	c, err := redis.New(cfg)
	if err != nil {
		t.Fatalf("failed to create redis cache: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Set a value
	err = c.Set(ctx, "key1", []byte("value1"), time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get it back
	val, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(val) != "value1" {
		t.Errorf("expected 'value1', got %q", string(val))
	}

	// Exists should be true
	exists, err := c.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("expected key to exist")
	}

	// Delete
	err = c.Delete(ctx, "key1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Exists should be false now
	exists, err = c.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists after delete failed: %v", err)
	}
	if exists {
		t.Error("expected key to not exist after delete")
	}
}

func TestReset(t *testing.T) {
	s := miniredis.RunT(t)

	cfg := &redis.Config{
		Addr:        s.Addr(),
		DialTimeout: time.Second,
	}

	c, err := redis.New(cfg)
	if err != nil {
		t.Fatalf("failed to create redis cache: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Create counter
	_, _, err = c.Increment(ctx, "counter", 100, time.Minute)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}

	// Reset it
	err = c.Reset(ctx, "counter")
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// GetCount should return 0
	count, err := c.GetCount(ctx, "counter")
	if err != nil {
		t.Fatalf("GetCount after reset failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
}
