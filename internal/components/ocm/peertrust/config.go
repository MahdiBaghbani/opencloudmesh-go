// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package peertrust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
)

// TrustGroupConfig defines a single trust group.
type TrustGroupConfig struct {
	TrustGroupID      string                             `json:"trustGroupId"`
	DirectoryServices []directoryservice.EndpointConfig  `json:"directoryServices"`
	Keys              []directoryservice.VerificationKey `json:"keys"`
	Enabled           bool                               `json:"enabled"`
	EnforceMembership bool                               `json:"enforceMembership"`
}

// LoadTrustGroupConfig loads a trust group config from a JSON file.
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
			return nil, fmt.Errorf("trust group config %s: directoryServices[%d] has invalid verification value %q (must be required, optional, or off)", path, i, ds.Verification)
		}
	}

	return &cfg, nil
}

// PolicyConfig defines the trust policy settings.
type PolicyConfig struct {
	AllowList []string `json:"allowList"`
	DenyList  []string `json:"denyList"`
}

// HasDenylist reports whether a nonempty denylist is configured.
func (c *PolicyConfig) HasDenylist() bool {
	return c != nil && len(c.DenyList) > 0
}

// HasAllowlist reports whether a nonempty allowlist is configured.
func (c *PolicyConfig) HasAllowlist() bool {
	return c != nil && len(c.AllowList) > 0
}
