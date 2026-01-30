package peertrust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
)

// TrustGroupConfig defines a single trust group (K2 format).
type TrustGroupConfig struct {
	TrustGroupID      string                          `json:"trust_group_id"`
	DirectoryServices []directoryservice.EndpointConfig  `json:"directory_services"`
	Keys              []directoryservice.VerificationKey `json:"keys"`
	Enabled           bool                            `json:"enabled"`
	EnforceMembership bool                            `json:"enforce_membership"`
}

// LoadTrustGroupConfig loads a trust group config from a K2 JSON file.
// Rejects the deprecated federation_id key with a clear migration message.
func LoadTrustGroupConfig(path string) (*TrustGroupConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust group config %s: %w", path, err)
	}

	// Preflight: reject banned keys before real decode.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing trust group config %s: %w", path, err)
	}
	_, hasFedID := raw["federation_id"]
	_, hasTGID := raw["trust_group_id"]
	if hasFedID && hasTGID {
		return nil, fmt.Errorf("trust group config %s contains both 'federation_id' and 'trust_group_id'; remove the deprecated 'federation_id' key", path)
	}
	if hasFedID {
		return nil, fmt.Errorf("trust group config %s: JSON key 'federation_id' has been renamed to 'trust_group_id'; please update your trust group configuration", path)
	}

	var cfg TrustGroupConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decoding trust group config %s: %w", path, err)
	}

	return &cfg, nil
}

// PolicyConfig defines the trust policy settings.
type PolicyConfig struct {
	GlobalEnforce bool     `json:"global_enforce"`
	AllowList     []string `json:"allow_list"`
	DenyList      []string `json:"deny_list"`
	ExemptList    []string `json:"exempt_list"`
}
