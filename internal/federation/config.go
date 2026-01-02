// Package federation implements Directory Service membership and trust policy.
package federation

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// FederationConfig defines a single federation (K2 format).
type FederationConfig struct {
	// FederationID is a unique identifier for this federation
	FederationID string `json:"federation_id"`

	// DirectoryServices are the DS URLs for this federation
	DirectoryServices []DirectoryServiceConfig `json:"directory_services"`

	// Keys are the public keys for JWS verification (multiple for rotation)
	Keys []FederationKey `json:"keys"`

	// Enabled controls whether this federation is active
	Enabled bool `json:"enabled"`

	// EnforceMembership requires peers to be DS members when enabled
	EnforceMembership bool `json:"enforce_membership"`
}

// DirectoryServiceConfig defines a Directory Service endpoint.
type DirectoryServiceConfig struct {
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// FederationKey is a public key for DS JWS verification.
type FederationKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Algorithm    string `json:"algorithm"` // RS256, ES256, Ed25519
	Active       bool   `json:"active"`
}

// LoadFederationConfig loads a federation config from a JSON file.
func LoadFederationConfig(path string) (*FederationConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read federation config: %w", err)
	}

	var cfg FederationConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse federation config: %w", err)
	}

	return &cfg, nil
}

// PolicyConfig defines the trust policy settings.
type PolicyConfig struct {
	// GlobalEnforce enables policy enforcement globally
	GlobalEnforce bool `json:"global_enforce"`

	// AllowList is the local allowlist of hosts
	AllowList []string `json:"allow_list"`

	// DenyList is the local denylist of hosts (always wins)
	DenyList []string `json:"deny_list"`

	// ExemptList bypasses federation membership checks
	ExemptList []string `json:"exempt_list"`
}

// MembershipCache stores the last-known-good membership for a federation.
type MembershipCache struct {
	FederationID string    `json:"federation_id"`
	LastRefresh  time.Time `json:"last_refresh"`
	Members      []Member  `json:"members"`
}

// Member represents a federation member server.
type Member struct {
	Host string `json:"host"` // host:port or just host
	Name string `json:"name,omitempty"`
}

// NormalizeHost normalizes a host for comparison.
// - Lowercases the host
// - Removes default ports (443 for https, 80 for http)
func NormalizeHost(host string, scheme string) string {
	host = strings.ToLower(host)

	// Remove default ports based on scheme
	if scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else if scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}

	return host
}

// HostMatches checks if two hosts match (port-aware).
func HostMatches(host1, host2 string) bool {
	// Already normalized by caller
	return host1 == host2
}
