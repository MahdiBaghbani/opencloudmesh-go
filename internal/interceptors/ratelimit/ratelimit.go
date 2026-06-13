// Package ratelimit provides a rate limiting interceptor using the cache subsystem.
package ratelimit

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config defines rate limiting parameters decoded from interceptor config.
type Config struct {
	RequestsPerWindow int64 `mapstructure:"requests_per_window"`
	WindowSeconds     int   `mapstructure:"window_seconds"`
}

// ApplyDefaults sets reasonable defaults for unconfigured fields.
func (c *Config) ApplyDefaults() {
	if c.RequestsPerWindow == 0 {
		c.RequestsPerWindow = 100
	}
	if c.WindowSeconds == 0 {
		c.WindowSeconds = int(cache.TTLRateLimit / time.Second)
	}
}

// Limiter provides rate limiting using a cache backend with trusted-proxy-aware keying.
type Limiter struct {
	cache   cache.Counter
	keyFunc func(*http.Request) string
	limit   int64
	window  time.Duration
	log     *slog.Logger
}

var (
	ErrMissingCache   = errors.New("ratelimit: cache not provided")
	ErrMissingKeyFunc = errors.New("ratelimit: key function not provided")
)

// New creates a ratelimit interceptor from narrow injected inputs.
func New(inputs Inputs, conf map[string]any, log *slog.Logger) (interceptors.Middleware, error) {
	log = logutil.NoopIfNil(log)

	if inputs.Cache == nil {
		return nil, ErrMissingCache
	}
	if inputs.KeyFunc == nil {
		return nil, ErrMissingKeyFunc
	}

	var c Config
	if err := svccfg.Decode(conf, &c); err != nil {
		return nil, err
	}
	c.ApplyDefaults()

	limiter := &Limiter{
		cache:   inputs.Cache,
		keyFunc: inputs.KeyFunc,
		limit:   c.RequestsPerWindow,
		window:  time.Duration(c.WindowSeconds) * time.Second,
		log:     log,
	}

	return limiter.Wrap, nil
}

// Wrap is the middleware function that applies rate limiting.
func (l *Limiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := l.keyFunc(r)
		count, resetAt, err := l.cache.Increment(r.Context(), "ratelimit:"+key, 1, l.window)
		if err != nil {
			l.log.Warn("rate limit check failed", "error", err)
			next.ServeHTTP(w, r)
			return
		}

		if count > l.limit {
			retryAfter := int(time.Until(resetAt).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			api.WriteTooManyRequests(w, "too many requests")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// WithKeyFunc returns a new Limiter with a custom key function.
func (l *Limiter) WithKeyFunc(fn func(*http.Request) string) *Limiter {
	return &Limiter{
		cache:   l.cache,
		keyFunc: fn,
		limit:   l.limit,
		window:  l.window,
		log:     l.log,
	}
}
