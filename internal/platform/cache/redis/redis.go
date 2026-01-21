// Package redis provides a Redis/Valkey cache driver with failover to in-memory.
package redis

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
)

// Config holds Redis connection configuration.
type Config struct {
	Addr         string        // Redis address (host:port)
	Password     string        // Optional password
	DB           int           // Database number
	DialTimeout  time.Duration // Connection timeout
	ReadTimeout  time.Duration // Read timeout
	WriteTimeout time.Duration // Write timeout
	PoolSize     int           // Connection pool size
}

// DefaultConfig returns sensible defaults for Redis connection.
func DefaultConfig() *Config {
	return &Config{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
	}
}

// Cache wraps a Redis client with automatic failover to in-memory cache.
// When Redis is unavailable, operations transparently fall back to memory.
type Cache struct {
	mu       sync.RWMutex
	config   *Config
	fallback *memory.Cache
	logger   *slog.Logger
	useFallback bool
}

// New creates a new Redis cache with in-memory fallback.
// For this reference implementation, we start with the fallback enabled
// since Redis integration requires an external dependency (go-redis).
// The architecture is ready for Redis when needed.
func New(cfg *Config, logger *slog.Logger) *Cache {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Create fallback cache with 1-minute cleanup interval
	fallback := memory.New(cache.TTLDiscovery, time.Minute)

	c := &Cache{
		config:      cfg,
		fallback:    fallback,
		logger:      logger,
		useFallback: true, // Start with fallback until Redis is connected
	}

	// Log that we're using fallback mode
	if logger != nil {
		logger.Info("cache initialized in memory-fallback mode",
			"redis_addr", cfg.Addr,
			"reason", "redis client not yet implemented")
	}

	return c
}

// Get retrieves a value by key.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Get(ctx, key)
	}

	// TODO: Implement Redis get when go-redis is added
	return c.fallback.Get(ctx, key)
}

// Set stores a value with the given TTL.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Set(ctx, key, value, ttl)
	}

	// TODO: Implement Redis set when go-redis is added
	return c.fallback.Set(ctx, key, value, ttl)
}

// Delete removes a key.
func (c *Cache) Delete(ctx context.Context, key string) error {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Delete(ctx, key)
	}

	// TODO: Implement Redis delete when go-redis is added
	return c.fallback.Delete(ctx, key)
}

// Exists checks if a key exists.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Exists(ctx, key)
	}

	// TODO: Implement Redis exists when go-redis is added
	return c.fallback.Exists(ctx, key)
}

// Increment adds delta to a counter.
func (c *Cache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Increment(ctx, key, delta, ttl)
	}

	// TODO: Implement Redis INCRBY when go-redis is added
	return c.fallback.Increment(ctx, key, delta, ttl)
}

// GetCount returns the current counter value.
func (c *Cache) GetCount(ctx context.Context, key string) (int64, error) {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.GetCount(ctx, key)
	}

	// TODO: Implement Redis get counter when go-redis is added
	return c.fallback.GetCount(ctx, key)
}

// Reset sets a counter to 0.
func (c *Cache) Reset(ctx context.Context, key string) error {
	c.mu.RLock()
	useFallback := c.useFallback
	c.mu.RUnlock()

	if useFallback {
		return c.fallback.Reset(ctx, key)
	}

	// TODO: Implement Redis reset when go-redis is added
	return c.fallback.Reset(ctx, key)
}

// Close releases resources.
func (c *Cache) Close() error {
	return c.fallback.Close()
}

// IsUsingFallback returns true if the cache is using in-memory fallback.
func (c *Cache) IsUsingFallback() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.useFallback
}

// Ensure Cache implements CacheWithCounter.
var _ cache.CacheWithCounter = (*Cache)(nil)
