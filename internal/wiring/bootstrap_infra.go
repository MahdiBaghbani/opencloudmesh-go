// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func buildUserAuth(opts BuildOpts) *identity.UserAuth {
	if opts.FastAuth {
		return identity.NewUserAuthFast()
	}

	return identity.NewUserAuth()
}

func buildKeyManager(
	cfg *config.Config,
	localIdentity localidentity.Identity,
	opts BuildOpts,
	logger *slog.Logger,
) (*crypto.KeyManager, error) {
	if opts.SkipCrypto {
		return nil, nil //nolint:nilnil // intentional: (nil, nil) denotes crypto skipped; caller checks for a nil KeyManager
	}

	keyDir := filepath.Dir(cfg.Signature.KeyPath)
	if keyDir != "" && keyDir != "." {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return nil, fmt.Errorf("create key directory %q: %w", keyDir, err)
		}
	}

	keyManager := crypto.NewKeyManagerWithFragment(
		cfg.Signature.KeyPath,
		localIdentity.Origin,
		cfg.Signature.KidFragment,
	)
	if err := keyManager.LoadOrGenerate(); err != nil {
		return nil, fmt.Errorf("initialize signing key: %w", err)
	}

	logger.Info("initialized signing key", "keyId", keyManager.GetKeyID())

	return keyManager, nil
}

func resolveOutboundConfig(cfg *config.Config, opts BuildOpts) *config.OutboundHTTPConfig {
	if opts.OutboundOverride != nil {
		return opts.OutboundOverride
	}

	return &cfg.OutboundHTTP
}

// buildCacheInstance builds the discovery cache. The memory driver is
// LRU-capped at the locked cardinality default; the redis driver is bounded
// server-side by operator maxmemory policy.
func buildCacheInstance(cfg *config.Config) (cache.CacheWithCounter, error) {
	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = config.BackendMemory
	}

	driversConfig := cfg.Cache.Drivers
	if cacheDriver == config.BackendMemory {
		driversConfig = withMemoryMaxEntries(driversConfig)
	}

	cacheInstance, err := cache.NewFromConfig(cacheDriver, driversConfig)
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	return cacheInstance, nil
}

// buildRatelimitCacheInstance builds the rate-limit cache as a TTL-only
// instance with no LRU bound: an LRU eviction would drop a live rate-limit
// window and let requests bypass the limit.
func buildRatelimitCacheInstance(cfg *config.Config) (cache.CacheWithCounter, error) {
	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = config.BackendMemory
	}

	cacheInstance, err := cache.NewFromConfig(cacheDriver, cfg.Cache.Drivers)
	if err != nil {
		return nil, fmt.Errorf("create ratelimit cache: %w", err)
	}

	return cacheInstance, nil
}

// withMemoryMaxEntries returns a copy of the drivers config with the memory
// driver bounded to the locked discovery cardinality cap.
func withMemoryMaxEntries(driversConfig map[string]any) map[string]any {
	out := make(map[string]any, len(driversConfig)+1)
	maps.Copy(out, driversConfig)

	memoryCfg := map[string]any{}

	if raw, ok := driversConfig["memory"]; ok {
		if m, ok := raw.(map[string]any); ok {
			maps.Copy(memoryCfg, m)
		}
	}

	memoryCfg["max_entries"] = memory.DefaultMaxEntries
	out["memory"] = memoryCfg

	return out
}

func buildPeerTrust(
	cfg *config.Config,
	localIdentity localidentity.Identity,
	rawHTTPClient *httpclient.Client,
	logger *slog.Logger,
	opts BuildOpts,
) (*peertrust.TrustGroupManager, *peertrust.PolicyEngine, error) { //nolint:unparam // error result kept for builder symmetry; trust-group load failures are logged and skipped by design, so it is always nil today
	if opts.SkipPeerTrust || !cfg.PeerTrust.Enabled {
		return nil, nil, nil
	}

	outboundCfg := resolveOutboundConfig(cfg, opts)
	refreshTimeout := time.Duration(outboundCfg.TimeoutMS) * time.Millisecond
	cacheConfig := peertrust.CacheConfig{
		TTL:      time.Duration(cfg.PeerTrust.MembershipCache.TTLSeconds) * time.Second,
		MaxStale: time.Duration(cfg.PeerTrust.MembershipCache.MaxStaleSeconds) * time.Second,
	}

	dirServiceClient := directoryservice.NewClient(rawHTTPClient, "required", logger)
	trustGroupMgr := peertrust.NewTrustGroupManager(cacheConfig, dirServiceClient, localIdentity.Scheme, logger, refreshTimeout)

	for _, cfgPath := range cfg.PeerTrust.ConfigPaths {
		tgCfg, err := peertrust.LoadTrustGroupConfig(cfgPath)
		if err != nil {
			logger.Warn("failed to load trust group config", "path", cfgPath, "error", err)

			continue
		}

		trustGroupMgr.AddTrustGroup(tgCfg)
		logger.Info("loaded trust group", "trust_group_id", tgCfg.TrustGroupID, "enabled", tgCfg.Enabled)
	}

	policyCfg := peertrustPolicyFromConfig(&cfg.PeerTrust.Policy)
	policyEngine := peertrust.NewPolicyEngine(policyCfg, trustGroupMgr, logger)
	logger.Info("peer trust enabled", "config_paths", len(cfg.PeerTrust.ConfigPaths))

	return trustGroupMgr, policyEngine, nil
}

func buildSigner(cfg *config.Config, keyManager *crypto.KeyManager) *crypto.RFC9421Signer {
	if keyManager == nil {
		return nil
	}

	signerOpts := crypto.RFC9421OptionsFromConfig(cfg.Signature)

	return crypto.NewRFC9421SignerWithOptions(keyManager, signerOpts)
}

func buildRealIPExtractor(cfg *config.Config) (*realip.TrustedProxies, error) {
	terminated := config.IsTLSModeTerminated(cfg)
	validator := config.IsValidatorMode(cfg)

	if terminated && len(cfg.Server.TrustedProxies) == 0 {
		return nil, errors.New("tls.mode=terminated requires at least one server.trusted_proxies entry")
	}

	if !validator && !terminated {
		return realip.NewTrustedProxies(cfg.Server.TrustedProxies), nil
	}

	tp, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("build real IP extractor: %w", err)
	}

	if terminated {
		return tp.EnableStrictForwarded(), nil
	}

	return tp, nil
}
