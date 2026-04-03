// Package policy owns local OCM policy derived from frozen config.
package policy

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"

// Evaluation holds the canonical OCM dimensions derived from local config.
type Evaluation struct {
	TokenExchangeCapable  bool
	RequiresTokenExchange bool
	PeerPolicy            string
}

// OpenCloudMeshPolicy interprets local config into canonical OCM dimensions.
// Constructed once at startup; config is immutable after that.
type OpenCloudMeshPolicy struct {
	evaluation Evaluation
}

// NewOpenCloudMeshPolicy creates the canonical local OCM policy.
func NewOpenCloudMeshPolicy(cfg *config.Config) *OpenCloudMeshPolicy {
	return &OpenCloudMeshPolicy{
		evaluation: Evaluation{
			TokenExchangeCapable:  cfg.TokenExchangeEnabled(),
			RequiresTokenExchange: cfg.WebDAVTokenExchange.Mode == "strict",
			PeerPolicy:            cfg.PeerPolicy,
		},
	}
}

// Evaluate returns the canonical local OCM policy snapshot.
func (p *OpenCloudMeshPolicy) Evaluate() Evaluation {
	return p.evaluation
}
