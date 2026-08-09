// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// LoaderOptions controls how configuration is loaded.
type LoaderOptions struct {
	// ConfigPath is the path to a TOML config file (optional).
	// If provided but file is missing or invalid, loading fails.
	ConfigPath string

	// ModeFlag is the --mode flag value (overrides config file mode).
	ModeFlag string

	// FlagOverrides are CLI flag values that override config file values.
	FlagOverrides FlagOverrides

	// Logger is accepted but not read by Load.
	Logger *slog.Logger
}

// FlagOverrides holds CLI flag values that override config file values.
type FlagOverrides struct {
	ListenAddr        *string
	PublicOrigin      *string
	ExternalBasePath  *string
	AdminUsername     *string
	AdminPassword     *string
	LoggingLevel      *string
	TokenExchangePath *string
}

// Load loads configuration with the following precedence (lowest to highest):
//  1. Determine effective mode: --mode flag > mode in config file > default (strict)
//  2. Start from mode preset defaults
//  3. Overlay TOML config file values (file overrides preset defaults)
//  4. Overlay CLI flags (flags override file values)
//  5. Overlay environment-variable overrides (env overrides both CLI flags
//     and TOML file values; env is the highest layer)
//  6. Validate enum fields
//
// Per-key precedence, from lowest to highest:
//   - the mode preset/default applies when the key is absent from the TOML
//     file, the CLI flags, and the environment;
//   - the TOML file value overrides the preset/default when set;
//   - CLI flags override the TOML file value when set (only keys with a flag);
//   - OCM_CONFIG_* environment variables override the CLI flag value (when a
//     flag exists for that key) and the TOML value, so env is the highest layer.
//
// An empty/unset OCM_CONFIG_* env var leaves the prior layer's value intact;
// a non-empty env var replaces it. See applyEnvOverrides for the supported
// variable list, which today includes OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK.
//
// If ConfigPath is provided but the file is missing, unreadable, or invalid TOML,
// Load returns an error (fail fast). Unknown/undecoded TOML keys fail the load.
func readConfigFile(configPath string) (fileConfig, toml.MetaData, error) {
	var fc fileConfig

	data, err := os.ReadFile(configPath) //nolint:gosec // G304: configPath is the operator-supplied --config CLI flag read once at startup, not request input
	if err != nil {
		return fc, toml.MetaData{}, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	md, err := toml.Decode(string(data), &fc)
	if err != nil {
		return fc, md, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}

	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keyStr := k.String()
			// http.services and http.interceptors store nested maps as
			// map[string]any; the TOML library cannot track leaf keys
			// within untyped values, so they appear undecoded by design.
			if strings.HasPrefix(keyStr, "http.services.") ||
				strings.HasPrefix(keyStr, "http.interceptors.") {
				continue
			}

			if isUnquotedMultiSegmentInstanceKey(k) {
				return fc, md, fmt.Errorf(
					"config file %s contains peer_compat instance host %q that must be a quoted TOML key; unquoted multi-segment hosts are not allowed",
					configPath, keyStr,
				)
			}

			keys = append(keys, keyStr)
		}

		if len(keys) > 0 {
			sort.Strings(keys)

			return fc, md, fmt.Errorf("config file %s contains unsupported keys: %s", configPath, strings.Join(keys, ", "))
		}
	}

	return fc, md, nil
}

func applyTLSDirDefaults(cfg *Config, md toml.MetaData) error {
	if !md.IsDefined("tls", "tls_dir") {
		return nil
	}

	if strings.TrimSpace(cfg.TLS.TLSDir) == "" {
		return errors.New("tls.tls_dir is set but empty; provide a path or remove the key")
	}

	tlsDir := strings.TrimSpace(cfg.TLS.TLSDir)
	if !md.IsDefined("tls", "self_signed_dir") {
		cfg.TLS.SelfSignedDir = filepath.Join(tlsDir, "certs")
	}

	if !md.IsDefined("tls", "acme", "storage_dir") {
		cfg.TLS.ACME.StorageDir = filepath.Join(tlsDir, "acme")
	}

	if !md.IsDefined("signature", "key_path") {
		cfg.Signature.KeyPath = filepath.Join(tlsDir, "keys", "signing.pem")
	}

	return nil
}

func validateExplicitEmptyPersistenceBackend(md toml.MetaData, fc fileConfig) error {
	if !md.IsDefined("persistence", "backend") {
		return nil
	}

	if fc.Persistence != nil && fc.Persistence.Backend == "" {
		return errors.New("persistence.backend is set but empty; provide a valid backend or remove the key")
	}

	return nil
}

func resolveEffectiveMode(fcMode, modeFlag string) (Mode, error) {
	modeStr := string(ModeStrict) // default
	if fcMode != "" {
		modeStr = fcMode
	}

	if modeFlag != "" {
		modeStr = modeFlag
	}

	return ParseMode(modeStr)
}

func normalizeLoadedConfig(cfg *Config, md toml.MetaData, fc fileConfig) error {
	if err := applyEnvOverrides(cfg); err != nil {
		return err
	}

	if err := normalizePeerMappingConfig(cfg); err != nil {
		return fmt.Errorf("invalid peer_compat configuration: %w", err)
	}

	if err := validatePeerMappingConfig(cfg); err != nil {
		return fmt.Errorf("invalid peer_compat configuration: %w", err)
	}

	applySignatureDefaults(cfg)

	if err := normalizeSignatureConfig(&cfg.Signature); err != nil {
		return err
	}

	if err := applyTLSDirDefaults(cfg, md); err != nil {
		return err
	}

	if err := validateExplicitEmptyPersistenceBackend(md, fc); err != nil {
		return err
	}

	return nil
}

func validateLoadedConfig(cfg *Config) error {
	if err := validateEnums(cfg); err != nil {
		return err
	}

	if err := validatePublicOrigin(cfg); err != nil {
		return err
	}

	validatedBasePath, err := localidentity.ValidateExternalBasePath(cfg.ExternalBasePath)
	if err != nil {
		return fmt.Errorf("invalid external_base_path: %w", err)
	}

	cfg.ExternalBasePath = validatedBasePath

	if err := validateOutboundTLSPaths(cfg); err != nil {
		return err
	}

	if err := validateProxyURL(cfg); err != nil {
		return err
	}

	return nil
}

// Load reads, merges, and validates configuration from the given loader options.
func Load(opts LoaderOptions) (*Config, error) {
	var (
		fc fileConfig
		md toml.MetaData
	)

	// Load TOML file when a config path is provided.
	if opts.ConfigPath != "" {
		var err error

		fc, md, err = readConfigFile(opts.ConfigPath)
		if err != nil {
			return nil, err
		}
	}

	mode, err := resolveEffectiveMode(fc.Mode, opts.ModeFlag)
	if err != nil {
		return nil, err
	}

	// Start from mode preset defaults.
	cfg := presetForMode(mode)

	// Overlay TOML file values.
	if opts.ConfigPath != "" {
		overlayFileConfig(cfg, &fc)
	}

	// Overlay CLI flag overrides.
	overlayFlags(cfg, opts.FlagOverrides)

	if err := normalizeLoadedConfig(cfg, md, fc); err != nil {
		return nil, err
	}

	if err := validateLoadedConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applySignatureDefaults(cfg *Config) {
	defaults := DefaultSignatureConfig()
	if cfg.Signature.Label == "" {
		cfg.Signature.Label = defaults.Label
	}

	if cfg.Signature.KidFragment == "" {
		cfg.Signature.KidFragment = defaults.KidFragment
	}

	if cfg.Signature.CreatedMaxAgeSeconds == 0 {
		cfg.Signature.CreatedMaxAgeSeconds = defaults.CreatedMaxAgeSeconds
	}

	if cfg.Signature.CreatedMaxSkewSeconds == 0 {
		cfg.Signature.CreatedMaxSkewSeconds = defaults.CreatedMaxSkewSeconds
	}

	if len(cfg.Signature.AllowedAlgorithms) == 0 {
		cfg.Signature.AllowedAlgorithms = append([]string(nil), defaults.AllowedAlgorithms...)
	}
}

func normalizeAllowedAlgorithm(alg string) (string, error) {
	normalized, err := sigalg.Normalize(alg)
	if err != nil {
		return "", fmt.Errorf("config: normalize signature algorithm: %w", err)
	}

	if !sigalg.IsImplemented(normalized) {
		return "", fmt.Errorf("unsupported algorithm %q", alg)
	}

	return normalized, nil
}

// NormalizeSignatureAllowedAlgorithms canonicalizes JOSE/native aliases,
// rejects empty/whitespace/symmetric/unknown entries, and dedupes while
// preserving first-seen order.
func NormalizeSignatureAllowedAlgorithms(algorithms []string) ([]string, error) {
	if len(algorithms) == 0 {
		return nil, errors.New("signature.allowed_algorithms must not be empty")
	}

	normalizedAlgs := make([]string, 0, len(algorithms))

	seen := make(map[string]struct{}, len(algorithms))
	for _, alg := range algorithms {
		if strings.TrimSpace(alg) == "" {
			return nil, errors.New("signature.allowed_algorithms must not contain empty values")
		}

		normalized, err := normalizeAllowedAlgorithm(alg)
		if err != nil {
			return nil, fmt.Errorf("signature.allowed_algorithms: %w", err)
		}

		if _, ok := seen[normalized]; ok {
			continue
		}

		seen[normalized] = struct{}{}
		normalizedAlgs = append(normalizedAlgs, normalized)
	}

	return normalizedAlgs, nil
}

func normalizeSignatureConfig(sig *SignatureConfig) error {
	normalized, err := NormalizeSignatureAllowedAlgorithms(sig.AllowedAlgorithms)
	if err != nil {
		return err
	}

	sig.AllowedAlgorithms = normalized

	return nil
}
