// Package cache provides caching with TTL support for discovery, JWKS, and rate limiting.
package cache

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("key not found")
	ErrExpired  = errors.New("key expired")
)

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
