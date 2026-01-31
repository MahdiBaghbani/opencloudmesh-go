package peertrust

import (
	"context"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// CacheConfig defines caching behavior for trust group membership.
type CacheConfig struct {
	TTL      time.Duration // stale threshold (default 6 hours)
	MaxStale time.Duration // maximum staleness before treating as unavailable (default 7 days)
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		TTL:      6 * time.Hour,
		MaxStale: 7 * 24 * time.Hour,
	}
}

// TrustGroupManager manages all configured trust groups.
type TrustGroupManager struct {
	mu                     sync.RWMutex
	trustGroups            map[string]*TrustGroup
	cacheConfig            CacheConfig
	directoryServiceClient *directoryservice.Client
	scheme                 string // for hostport.Normalize (from PublicScheme)
	logger                 *slog.Logger
	refreshTimeout         time.Duration
}

// TrustGroup represents a single trust group with its state.
type TrustGroup struct {
	config            *TrustGroupConfig
	memberAuthorities []memberAuthority            // precomputed normalized host authorities
	directoryListings []directoryservice.Listing   // raw verified listings
	lastRefresh       time.Time
	refreshing        bool
	refreshMu         sync.Mutex
}

// memberAuthority is a precomputed member for fast isMemberOf comparison.
type memberAuthority struct {
	normalized string // result of hostport.Normalize(u.Host, scheme) at refresh time
}

// NewTrustGroupManager creates a new trust group manager.
// scheme enables scheme-aware host normalization via hostport.Normalize.
func NewTrustGroupManager(
	cacheConfig CacheConfig,
	directoryServiceClient *directoryservice.Client,
	scheme string,
	logger *slog.Logger,
	refreshTimeout time.Duration,
) *TrustGroupManager {
	logger = logutil.NoopIfNil(logger)
	if refreshTimeout <= 0 {
		refreshTimeout = 10 * time.Second
	}
	return &TrustGroupManager{
		trustGroups:            make(map[string]*TrustGroup),
		cacheConfig:            cacheConfig,
		directoryServiceClient: directoryServiceClient,
		scheme:                 scheme,
		logger:                 logger,
		refreshTimeout:         refreshTimeout,
	}
}

// AddTrustGroup registers a trust group config (loaded from K2 JSON).
func (m *TrustGroupManager) AddTrustGroup(cfg *TrustGroupConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.trustGroups[cfg.TrustGroupID] = &TrustGroup{
		config:      cfg,
		lastRefresh: time.Time{}, // never refreshed
	}
}

// IsMember checks if a host is a member of any enabled trust group (M1 union).
func (m *TrustGroupManager) IsMember(ctx context.Context, host string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, tg := range m.trustGroups {
		if !tg.config.Enabled {
			continue
		}

		m.triggerRefreshIfNeeded(ctx, tg)

		if m.isMemberOf(tg, host) {
			return true
		}
	}

	return false
}

// isMemberOf checks if a host matches any precomputed member authority in the trust group.
func (m *TrustGroupManager) isMemberOf(tg *TrustGroup, host string) bool {
	normalized, err := hostport.Normalize(host, m.scheme)
	if err != nil {
		return false
	}
	for _, authority := range tg.memberAuthorities {
		if authority.normalized == normalized {
			return true
		}
	}
	return false
}

// triggerRefreshIfNeeded triggers an async refresh if the cache is stale.
// Uses a detached context with timeout so it is not canceled when the request ends.
func (m *TrustGroupManager) triggerRefreshIfNeeded(_ context.Context, tg *TrustGroup) {
	age := time.Since(tg.lastRefresh)

	if age > m.cacheConfig.TTL {
		enabledCount := 0
		for _, ds := range tg.config.DirectoryServices {
			if ds.Enabled {
				enabledCount++
			}
		}
		if enabledCount == 0 {
			enabledCount = 1
		}
		timeout := m.refreshTimeout * time.Duration(enabledCount)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			m.refreshTrustGroup(ctx, tg)
		}()
	}
}

// refreshTrustGroup fetches and updates membership for a trust group.
func (m *TrustGroupManager) refreshTrustGroup(ctx context.Context, tg *TrustGroup) {
	tg.refreshMu.Lock()
	if tg.refreshing {
		tg.refreshMu.Unlock()
		return
	}
	tg.refreshing = true
	tg.refreshMu.Unlock()

	defer func() {
		tg.refreshMu.Lock()
		tg.refreshing = false
		tg.refreshMu.Unlock()
	}()

	m.logger.Info("refreshing trust group membership", "trust_group", tg.config.TrustGroupID)

	var allListings []directoryservice.Listing

	for _, ds := range tg.config.DirectoryServices {
		if !ds.Enabled {
			continue
		}

		listing, err := m.directoryServiceClient.FetchListing(ctx, ds.URL, tg.config.Keys)
		if err != nil {
			m.logger.Warn("failed to fetch directory service listing",
				"trust_group", tg.config.TrustGroupID,
				"directory_service_url", ds.URL,
				"error", err)
			continue // keep cache if fetch fails
		}

		allListings = append(allListings, *listing)
	}

	if len(allListings) > 0 {
		authorities := m.precomputeAuthorities(allListings)

		m.mu.Lock()
		tg.directoryListings = allListings
		tg.memberAuthorities = authorities
		tg.lastRefresh = time.Now()
		m.mu.Unlock()

		m.logger.Info("updated trust group membership",
			"trust_group", tg.config.TrustGroupID,
			"member_count", len(authorities))
	}
}

// precomputeAuthorities extracts and normalizes host authorities from listings.
func (m *TrustGroupManager) precomputeAuthorities(listings []directoryservice.Listing) []memberAuthority {
	seen := make(map[string]bool)
	var result []memberAuthority

	for _, listing := range listings {
		for _, server := range listing.Servers {
			u, err := url.Parse(server.URL)
			if err != nil {
				continue
			}
			normalized, err := hostport.Normalize(u.Host, m.scheme)
			if err != nil {
				continue
			}
			if !seen[normalized] {
				seen[normalized] = true
				result = append(result, memberAuthority{normalized: normalized})
			}
		}
	}

	return result
}

// GetTrustGroups returns the configured trust groups.
func (m *TrustGroupManager) GetTrustGroups() []*TrustGroupConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*TrustGroupConfig
	for _, tg := range m.trustGroups {
		result = append(result, tg.config)
	}
	return result
}

// GetDirectoryListings returns the current verified Directory Service listings
// for enabled trust groups. Consumed by ocmaux handler (Phase 5).
func (m *TrustGroupManager) GetDirectoryListings(ctx context.Context) []directoryservice.Listing {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allListings []directoryservice.Listing

	for _, tg := range m.trustGroups {
		if !tg.config.Enabled {
			continue
		}

		if !tg.lastRefresh.IsZero() && time.Since(tg.lastRefresh) < m.cacheConfig.MaxStale {
			allListings = append(allListings, tg.directoryListings...)
		}

		m.triggerRefreshIfNeeded(ctx, tg)
	}

	return allListings
}

// SetCacheForTesting allows tests to set cache directly.
func (m *TrustGroupManager) SetCacheForTesting(trustGroupID string, listings []directoryservice.Listing, lastRefresh time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tg, ok := m.trustGroups[trustGroupID]
	if !ok {
		return
	}

	tg.directoryListings = listings
	tg.lastRefresh = lastRefresh
	tg.memberAuthorities = m.precomputeAuthorities(listings)
}

