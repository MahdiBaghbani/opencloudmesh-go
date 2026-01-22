// Package redis provides a Redis/Valkey cache driver using valkey-go.
// Fail-fast: when cache.driver=redis is configured, startup fails if Redis is unreachable.
package redis

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
)

func init() {
	cache.RegisterDriver("redis", func(config map[string]any) cache.CacheWithCounter {
		cfg := DefaultConfig()
		if config != nil {
			if v, ok := config["addr"].(string); ok && v != "" {
				cfg.Addr = v
			}
			if v, ok := config["password"].(string); ok {
				cfg.Password = v
			}
			if v, ok := config["db"]; ok {
				if db, ok := toInt(v); ok {
					cfg.DB = db
				}
			}
			if v, ok := config["dial_timeout_ms"]; ok {
				if ms, ok := toInt(v); ok && ms > 0 {
					cfg.DialTimeout = time.Duration(ms) * time.Millisecond
				}
			}
			if v, ok := config["conn_timeout_ms"]; ok {
				if ms, ok := toInt(v); ok && ms > 0 {
					cfg.ConnTimeout = time.Duration(ms) * time.Millisecond
				}
			}
			if v, ok := config["default_ttl_seconds"]; ok {
				if secs, ok := toInt(v); ok && secs > 0 {
					cfg.DefaultTTL = time.Duration(secs) * time.Second
				}
			}
		}

		c, err := New(cfg)
		if err != nil {
			// Fail-fast: panic on connection failure when redis driver is explicitly configured
			panic(fmt.Sprintf("redis cache driver failed to initialize: %v", err))
		}
		return c
	})
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// Config holds Redis connection configuration.
type Config struct {
	Addr            string        // Redis address (host:port)
	Password        string        // Optional password
	DB              int           // Database number
	DialTimeout     time.Duration // Connection timeout
	ConnTimeout     time.Duration // Read/write timeout per connection (valkey-go uses one timeout for both)
	DefaultTTL      time.Duration // Default TTL for cache entries
}

// DefaultConfig returns sensible defaults for Redis connection.
func DefaultConfig() *Config {
	return &Config{
		Addr:        "localhost:6379",
		Password:    "",
		DB:          0,
		DialTimeout: 5 * time.Second,
		ConnTimeout: 3 * time.Second,
		DefaultTTL:  15 * time.Minute,
	}
}

// Cache implements cache.CacheWithCounter using Redis/Valkey.
type Cache struct {
	client        valkey.Client
	defaultTTL    time.Duration
	counterScript *valkey.Lua
}

// Lua script for atomic counter increment with TTL only on first create.
// Returns [count, ttl_ms]. TTL is set only when key is new (count equals delta).
const counterLuaScript = `
local current = redis.call('INCRBY', KEYS[1], ARGV[1])
if current == tonumber(ARGV[1]) then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`

// New creates a new Redis cache with fail-fast behavior.
// Returns an error if Redis is unreachable or the counter script fails validation.
func New(cfg *Config) (*Cache, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Build valkey client options
	opts := valkey.ClientOption{
		InitAddress: []string{cfg.Addr},
		Password:    cfg.Password,
		SelectDB:    cfg.DB,
		Dialer: net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		},
		ConnWriteTimeout: cfg.ConnTimeout, // valkey-go uses this for both read and write
		DisableCache:     true,            // disable client-side caching (not needed for our use case)
	}

	client, err := valkey.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create redis client: %w", err)
	}

	c := &Cache{
		client:        client,
		defaultTTL:    cfg.DefaultTTL,
		counterScript: valkey.NewLuaScript(counterLuaScript),
	}

	// Fail-fast: verify connection and script execution work
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := c.healthCheck(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis health check failed: %w", err)
	}

	return c, nil
}

// healthCheck verifies Redis is reachable and the counter script can execute.
func (c *Cache) healthCheck(ctx context.Context) error {
	// Test basic connectivity with PING
	resp := c.client.Do(ctx, c.client.B().Ping().Build())
	if err := resp.Error(); err != nil {
		return fmt.Errorf("PING failed: %w", err)
	}

	// Test counter script execution with a temporary key
	testKey := "__ocm_cache_health_check__"
	result := c.counterScript.Exec(ctx, c.client, []string{testKey}, []string{"1", "1000"})
	if err := result.Error(); err != nil {
		return fmt.Errorf("counter script test failed: %w", err)
	}

	// Clean up test key
	c.client.Do(ctx, c.client.B().Del().Key(testKey).Build())

	return nil
}

// Get retrieves a value by key.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	resp := c.client.Do(ctx, c.client.B().Get().Key(key).Build())
	if err := resp.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, cache.ErrNotFound
		}
		return nil, err
	}

	data, err := resp.AsBytes()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Set stores a value with the given TTL.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	resp := c.client.Do(ctx, c.client.B().Set().Key(key).Value(string(value)).Px(ttl).Build())
	return resp.Error()
}

// Delete removes a key.
func (c *Cache) Delete(ctx context.Context, key string) error {
	resp := c.client.Do(ctx, c.client.B().Del().Key(key).Build())
	return resp.Error()
}

// Exists checks if a key exists.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	resp := c.client.Do(ctx, c.client.B().Exists().Key(key).Build())
	if err := resp.Error(); err != nil {
		return false, err
	}
	count, err := resp.AsInt64()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Increment adds delta to a counter and returns the new value and reset time.
func (c *Cache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, time.Time, error) {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	ttlMs := ttl.Milliseconds()
	result := c.counterScript.Exec(ctx, c.client, []string{key}, []string{
		strconv.FormatInt(delta, 10),
		strconv.FormatInt(ttlMs, 10),
	})

	if err := result.Error(); err != nil {
		return 0, time.Time{}, err
	}

	arr, err := result.AsIntSlice()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("unexpected script result: %w", err)
	}
	if len(arr) != 2 {
		return 0, time.Time{}, fmt.Errorf("unexpected script result length: %d", len(arr))
	}

	count := arr[0]
	remainingTTLMs := arr[1]

	// Compute resetAt from remaining TTL
	resetAt := time.Now().Add(time.Duration(remainingTTLMs) * time.Millisecond)

	return count, resetAt, nil
}

// GetCount returns the current counter value.
func (c *Cache) GetCount(ctx context.Context, key string) (int64, error) {
	resp := c.client.Do(ctx, c.client.B().Get().Key(key).Build())
	if err := resp.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return 0, nil
		}
		return 0, err
	}

	val, err := resp.AsInt64()
	if err != nil {
		// Key exists but is not an integer (shouldn't happen for counters)
		return 0, err
	}
	return val, nil
}

// Reset sets a counter to 0 by deleting the key.
func (c *Cache) Reset(ctx context.Context, key string) error {
	return c.Delete(ctx, key)
}

// Close releases resources.
func (c *Cache) Close() error {
	c.client.Close()
	return nil
}

// Ensure Cache implements CacheWithCounter.
var _ cache.CacheWithCounter = (*Cache)(nil)
