// Package memory provides an in-memory cache implementation with TTL support.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
)

func init() {
	cache.RegisterDriver("memory", func(config map[string]any) cache.Cache {
		// Apply defaults (Reva-style)
		defaultTTL := 15 * time.Minute
		cleanupInterval := 5 * time.Minute

		// Override from config if present
		if config != nil {
			if v, ok := config["default_ttl_seconds"]; ok {
				if secs, ok := toInt(v); ok && secs > 0 {
					defaultTTL = time.Duration(secs) * time.Second
				}
			}
			if v, ok := config["cleanup_interval_seconds"]; ok {
				if secs, ok := toInt(v); ok && secs > 0 {
					cleanupInterval = time.Duration(secs) * time.Second
				}
			}
		}

		return New(defaultTTL, cleanupInterval)
	})
}

// toInt converts various numeric types to int.
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

// item represents a cached value with expiration.
type item struct {
	value     []byte
	expiresAt time.Time
}

func (i *item) isExpired() bool {
	return time.Now().After(i.expiresAt)
}

// counterItem represents a counter with expiration.
type counterItem struct {
	value     int64
	expiresAt time.Time
}

func (c *counterItem) isExpired() bool {
	return time.Now().After(c.expiresAt)
}

// Cache is an in-memory cache with TTL support.
type Cache struct {
	mu         sync.RWMutex
	items      map[string]*item
	counters   map[string]*counterItem
	defaultTTL time.Duration
	stopClean  chan struct{}
}

// New creates a new in-memory cache.
// cleanupInterval specifies how often to run the cleanup goroutine (0 disables).
func New(defaultTTL time.Duration, cleanupInterval time.Duration) *Cache {
	c := &Cache{
		items:      make(map[string]*item),
		counters:   make(map[string]*counterItem),
		defaultTTL: defaultTTL,
		stopClean:  make(chan struct{}),
	}

	if cleanupInterval > 0 {
		go c.cleanupLoop(cleanupInterval)
	}

	return c
}

func (c *Cache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.deleteExpired()
		case <-c.stopClean:
			return
		}
	}
}

func (c *Cache) deleteExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expiresAt) {
			delete(c.items, k)
		}
	}
	for k, v := range c.counters {
		if now.After(v.expiresAt) {
			delete(c.counters, k)
		}
	}
}

// Get retrieves a value by key.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok {
		return nil, cache.ErrNotFound
	}

	if item.isExpired() {
		return nil, cache.ErrExpired
	}

	// Return a copy to prevent mutation
	result := make([]byte, len(item.value))
	copy(result, item.value)
	return result, nil
}

// Set stores a value with the given TTL.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	// Make a copy of the value
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &item{
		value:     valueCopy,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a key.
func (c *Cache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
	return nil
}

// Exists checks if a key exists and is not expired.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok {
		return false, nil
	}

	return !item.isExpired(), nil
}

// Increment adds delta to a counter and returns the new value and reset time.
func (c *Cache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, time.Time, error) {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	counter, ok := c.counters[key]
	if !ok || counter.isExpired() {
		// Create new counter
		expiresAt := time.Now().Add(ttl)
		c.counters[key] = &counterItem{
			value:     delta,
			expiresAt: expiresAt,
		}
		return delta, expiresAt, nil
	}

	counter.value += delta
	return counter.value, counter.expiresAt, nil
}

// GetCount returns the current counter value.
func (c *Cache) GetCount(ctx context.Context, key string) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	counter, ok := c.counters[key]
	if !ok || counter.isExpired() {
		return 0, nil
	}

	return counter.value, nil
}

// Reset sets a counter to 0.
func (c *Cache) Reset(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.counters, key)
	return nil
}

// Close stops the cleanup goroutine.
func (c *Cache) Close() error {
	close(c.stopClean)
	return nil
}

// Ensure Cache implements CacheWithCounter.
var _ cache.CacheWithCounter = (*Cache)(nil)
