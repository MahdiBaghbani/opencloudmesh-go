package redis_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/redis"
)

func TestNew_FailFastUnreachable(t *testing.T) {
	// Test that New() fails fast when Redis is unreachable
	cfg := &redis.Config{
		Addr:        "localhost:59999", // Unlikely to have Redis running here
		DialTimeout: 100 * 1e6,         // 100ms for fast failure
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
