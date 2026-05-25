package peertrust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
)

// TrustGroupConfig defines a single trust group (K2 format).
type TrustGroupConfig struct {
	TrustGroupID      string                             `json:"trust_group_id"`
	DirectoryServices []directoryservice.EndpointConfig  `json:"directory_services"`
	Keys              []directoryservice.VerificationKey `json:"keys"`
	Enabled           bool                               `json:"enabled"`
	EnforceMembership bool                               `json:"enforce_membership"`
}

// LoadTrustGroupConfig loads a trust group config from a K2 JSON file.
// Unknown JSON keys fail the load.
func LoadTrustGroupConfig(path string) (*TrustGroupConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust group config %s: %w", path, err)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg TrustGroupConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding trust group config %s: %w", path, err)
	}
	if err := dec.Decode(&json.RawMessage{}); err != io.EOF {
		return nil, fmt.Errorf("trust group config %s: unexpected trailing content after JSON object", path)
	}

	// Validate directory service verification policies.
	for i, ds := range cfg.DirectoryServices {
		switch ds.Verification {
		case "", "required", "optional", "off":
			// valid
		default:
			return nil, fmt.Errorf("trust group config %s: directory_services[%d] has invalid verification value %q (must be required, optional, or off)", path, i, ds.Verification)
		}
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
