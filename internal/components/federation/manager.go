package federation

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// CacheConfig defines caching behavior for federation membership.
type CacheConfig struct {
	// TTL is the stale threshold (default 6 hours)
	TTL time.Duration
	// MaxStale is the maximum staleness before treating as unavailable (default 7 days)
	MaxStale time.Duration
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		TTL:      6 * time.Hour,
		MaxStale: 7 * 24 * time.Hour,
	}
}

// FederationManager manages all configured federations.
type FederationManager struct {
	mu                  sync.RWMutex
	federations         map[string]*Federation
	cacheConfig         CacheConfig
	dsClient            *DirectoryServiceClient
	logger              *slog.Logger
	refreshTimeoutPerDS time.Duration // timeout per directory service for refresh operations
}

// Federation represents a single federation with its state.
type Federation struct {
	Config       *FederationConfig
	Cache        *MembershipCache
	refreshing   bool
	refreshMu    sync.Mutex
}

// NewFederationManager creates a new federation manager.
// refreshTimeoutPerDS is the timeout per directory service for refresh operations (e.g., outbound_http.timeout_ms).
func NewFederationManager(cacheConfig CacheConfig, dsClient *DirectoryServiceClient, logger *slog.Logger, refreshTimeoutPerDS time.Duration) *FederationManager {
	if refreshTimeoutPerDS <= 0 {
		refreshTimeoutPerDS = 10 * time.Second // fallback
	}
	return &FederationManager{
		federations:         make(map[string]*Federation),
		cacheConfig:         cacheConfig,
		dsClient:            dsClient,
		logger:              logger,
		refreshTimeoutPerDS: refreshTimeoutPerDS,
	}
}

// AddFederation adds a federation to the manager.
func (fm *FederationManager) AddFederation(cfg *FederationConfig) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.federations[cfg.FederationID] = &Federation{
		Config: cfg,
		Cache: &MembershipCache{
			FederationID: cfg.FederationID,
			LastRefresh:  time.Time{}, // Never refreshed
			Members:      nil,
		},
	}
}

// IsMember checks if a host is a member of any enabled federation (M1 union).
func (fm *FederationManager) IsMember(ctx context.Context, host string) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	host = strings.ToLower(host)

	for _, fed := range fm.federations {
		if !fed.Config.Enabled {
			continue
		}

		// Trigger refresh if stale
		fm.triggerRefreshIfNeeded(ctx, fed)

		// Check membership in cache
		if fm.isMemberOf(host, fed.Cache) {
			return true
		}
	}

	return false
}

// isMemberOf checks if a host is in the membership cache.
func (fm *FederationManager) isMemberOf(host string, cache *MembershipCache) bool {
	if cache == nil || cache.Members == nil {
		return false
	}

	for _, m := range cache.Members {
		memberHost := strings.ToLower(m.Host)
		if memberHost == host {
			return true
		}
		// Handle host with/without default port
		if strings.TrimSuffix(memberHost, ":443") == strings.TrimSuffix(host, ":443") {
			return true
		}
	}

	return false
}

// triggerRefreshIfNeeded triggers an async refresh if the cache is stale.
// Uses a detached context with timeout so it isn't canceled when the request ends
// but still has a bounded duration.
func (fm *FederationManager) triggerRefreshIfNeeded(_ context.Context, fed *Federation) {
	if fed.Cache == nil {
		return
	}

	age := time.Since(fed.Cache.LastRefresh)

	if age > fm.cacheConfig.TTL {
		// Stale - trigger async refresh with detached context
		// Compute timeout: timeoutPerDS * (number of enabled directory services)
		dsCount := 0
		for _, ds := range fed.Config.DirectoryServices {
			if ds.Enabled {
				dsCount++
			}
		}
		if dsCount == 0 {
			dsCount = 1 // at least one
		}
		timeout := fm.refreshTimeoutPerDS * time.Duration(dsCount)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			fm.refreshFederation(ctx, fed)
		}()
	}
}

// refreshFederation fetches and updates membership for a federation.
func (fm *FederationManager) refreshFederation(ctx context.Context, fed *Federation) {
	fed.refreshMu.Lock()
	if fed.refreshing {
		fed.refreshMu.Unlock()
		return // Already refreshing
	}
	fed.refreshing = true
	fed.refreshMu.Unlock()

	defer func() {
		fed.refreshMu.Lock()
		fed.refreshing = false
		fed.refreshMu.Unlock()
	}()

	fm.logger.Info("refreshing federation membership", "federation", fed.Config.FederationID)

	// Fetch from all enabled directory services
	var allMembers []Member

	for _, ds := range fed.Config.DirectoryServices {
		if !ds.Enabled {
			continue
		}

		members, err := fm.dsClient.FetchMembership(ctx, ds.URL, fed.Config.Keys)
		if err != nil {
			fm.logger.Warn("failed to fetch DS membership",
				"federation", fed.Config.FederationID,
				"ds_url", ds.URL,
				"error", err)
			continue // F1: keep cache if fetch fails
		}

		allMembers = append(allMembers, members...)
	}

	// Update cache if we got any members
	if len(allMembers) > 0 {
		fm.mu.Lock()
		fed.Cache = &MembershipCache{
			FederationID: fed.Config.FederationID,
			LastRefresh:  time.Now(),
			Members:      deduplicateMembers(allMembers),
		}
		fm.mu.Unlock()

		fm.logger.Info("updated federation membership",
			"federation", fed.Config.FederationID,
			"member_count", len(fed.Cache.Members))
	}
}

// deduplicateMembers removes duplicate hosts from the member list.
func deduplicateMembers(members []Member) []Member {
	seen := make(map[string]bool)
	var result []Member

	for _, m := range members {
		key := strings.ToLower(m.Host)
		if !seen[key] {
			seen[key] = true
			result = append(result, m)
		}
	}

	return result
}

// GetAllMembers returns all known members from all enabled federations.
func (fm *FederationManager) GetAllMembers(ctx context.Context) []Member {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var allMembers []Member

	for _, fed := range fm.federations {
		if !fed.Config.Enabled {
			continue
		}

		// Check if cache is too stale
		if fed.Cache != nil && time.Since(fed.Cache.LastRefresh) < fm.cacheConfig.MaxStale {
			allMembers = append(allMembers, fed.Cache.Members...)
		}

		// Trigger refresh if needed
		fm.triggerRefreshIfNeeded(ctx, fed)
	}

	return deduplicateMembers(allMembers)
}

// GetFederations returns the list of configured federations.
func (fm *FederationManager) GetFederations() []*FederationConfig {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var result []*FederationConfig
	for _, fed := range fm.federations {
		result = append(result, fed.Config)
	}
	return result
}

// SetCacheForTesting allows tests to set cache directly.
func (fm *FederationManager) SetCacheForTesting(federationID string, cache *MembershipCache) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fed, ok := fm.federations[federationID]; ok {
		fed.Cache = cache
	}
}
