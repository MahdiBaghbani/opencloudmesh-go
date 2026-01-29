package peertrust

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
)

// TrustGroupConfig defines a single trust group (K2 format).
// JSON tag stays as federation_id until Phase 6 strict-break rename.
type TrustGroupConfig struct {
	TrustGroupID      string                          `json:"federation_id"`
	DirectoryServices []directoryservice.EndpointConfig  `json:"directory_services"`
	Keys              []directoryservice.VerificationKey `json:"keys"`
	Enabled           bool                            `json:"enabled"`
	EnforceMembership bool                            `json:"enforce_membership"`
}

// LoadTrustGroupConfig loads a trust group config from a K2 JSON file.
func LoadTrustGroupConfig(path string) (*TrustGroupConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust group config: %w", err)
	}

	var cfg TrustGroupConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse trust group config: %w", err)
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

// Member represents a trust group member server (temporary bridge type).
// Used by handlers.go (still in federation/) via GetAllMembers() until Phase 5.
type Member struct {
	Host string `json:"host"`
	Name string `json:"name,omitempty"`
}
