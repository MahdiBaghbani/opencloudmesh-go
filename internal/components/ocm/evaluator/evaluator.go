// Package evaluator owns the local config-to-canonical interpretation for opencloudmesh-go.
package evaluator

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// LocalEvaluation holds the three canonical OCM dimensions derived from local config.
type LocalEvaluation struct {
	TokenExchangeCapable  bool
	RequiresTokenExchange bool
	PeerPolicy            string
}

// LocalEvaluator interprets local config into canonical OCM dimensions.
// Constructed once at startup; config is immutable after that.
type LocalEvaluator struct {
	cfg *config.Config
}

// NewLocalEvaluator creates a LocalEvaluator from an immutable config.
func NewLocalEvaluator(cfg *config.Config) *LocalEvaluator {
	return &LocalEvaluator{cfg: cfg}
}

// Evaluate returns the canonical local evaluation. Cheap to call; no allocation beyond the struct copy.
func (e *LocalEvaluator) Evaluate() LocalEvaluation {
	return LocalEvaluation{
		TokenExchangeCapable:  e.cfg.TokenExchangeEnabled(),
		RequiresTokenExchange: e.cfg.WebDAVTokenExchange.Mode == "strict",
		PeerPolicy:            e.cfg.PeerPolicy,
	}
}
