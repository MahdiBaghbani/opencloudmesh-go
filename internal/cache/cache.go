// Package cache provides caching with TTL support for discovery, JWKS, and rate limiting.
// Uses a Reva-style registry pattern: drivers register via init(), callers use NewDefault() or NewFromConfig().
package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("key not found")
	ErrExpired  = errors.New("key expired")
)

// Driver registry (Reva-style)
var (
	driversMu sync.RWMutex
	drivers   = make(map[string]DriverFactory)
)

// DriverFactory creates a new cache instance with driver-specific config.
// The config map comes from [cache.drivers.<name>] in TOML. May be nil.
// Factory must apply its own defaults (Reva-style ApplyDefaults).
type DriverFactory func(config map[string]any) Cache

// RegisterDriver registers a cache driver by name. Called from driver init().
func RegisterDriver(name string, factory DriverFactory) {
	driversMu.Lock()
	defer driversMu.Unlock()
	drivers[name] = factory
}

// NewDefault returns the default cache (in-memory with default settings).
// Panics if the memory driver is not registered (caller must blank-import internal/cache/loader).
func NewDefault() Cache {
	return newByDriver("memory", nil)
}

// NewFromConfig returns a cache based on the driver name and driver-specific config.
// If driver is empty, defaults to "memory".
// The driversConfig map contains per-driver configs keyed by driver name (from [cache.drivers.*]).
// If driversConfig is nil or missing the driver key, the driver's defaults are used.
// Returns an error if the driver is unknown.
func NewFromConfig(driver string, driversConfig map[string]any) (Cache, error) {
	if driver == "" {
		driver = "memory"
	}

	driversMu.RLock()
	factory, ok := drivers[driver]
	driversMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown cache driver %q: only 'memory' is supported in this release", driver)
	}

	// Extract driver-specific config (may be nil)
	var driverConfig map[string]any
	if driversConfig != nil {
		if cfg, ok := driversConfig[driver]; ok {
			if cfgMap, ok := cfg.(map[string]any); ok {
				driverConfig = cfgMap
			}
		}
	}

	return factory(driverConfig), nil
}

// newByDriver returns a cache for the named driver, panicking if not found.
func newByDriver(name string, config map[string]any) Cache {
	driversMu.RLock()
	factory, ok := drivers[name]
	driversMu.RUnlock()

	if !ok {
		panic(fmt.Sprintf("cache driver %q not registered; ensure internal/cache/loader is imported", name))
	}

	return factory(config)
}

// Cache provides TTL-based key-value storage.
type Cache interface {
	// Get retrieves a value by key. Returns ErrNotFound if not present.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with the given TTL. If TTL is 0, use default.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a key.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists and is not expired.
	Exists(ctx context.Context, key string) (bool, error)

	// Close releases resources.
	Close() error
}

// Counter provides atomic increment/decrement operations for rate limiting.
type Counter interface {
	// Increment adds delta to the counter and returns the new value.
	// If the key doesn't exist, it's created with the given TTL.
	Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)

	// Get returns the current counter value. Returns 0 if not found.
	GetCount(ctx context.Context, key string) (int64, error)

	// Reset sets the counter to 0.
	Reset(ctx context.Context, key string) error
}

// CacheWithCounter combines Cache and Counter interfaces.
type CacheWithCounter interface {
	Cache
	Counter
}

// Default TTLs for different cache categories.
const (
	TTLDiscovery = 15 * time.Minute // Discovery document cache
	TTLJWKs      = 15 * time.Minute // JWKS cache
	TTLRateLimit = 1 * time.Minute  // Rate limit window
)
