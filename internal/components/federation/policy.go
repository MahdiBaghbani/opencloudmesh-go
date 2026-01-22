package federation

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// PolicyDecision represents the result of a policy check.
type PolicyDecision struct {
	Allowed     bool
	Reason      string
	ReasonCode  string
	Authenticated bool // true if peer was authenticated via signature
}

// PolicyEngine evaluates allow/deny and federation membership.
type PolicyEngine struct {
	cfg             *PolicyConfig
	federationMgr   *FederationManager
	logger          *slog.Logger
	mu              sync.RWMutex
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine(cfg *PolicyConfig, fedMgr *FederationManager, logger *slog.Logger) *PolicyEngine {
	return &PolicyEngine{
		cfg:           cfg,
		federationMgr: fedMgr,
		logger:        logger,
	}
}

// Evaluate checks if a peer is allowed based on policy.
// peerHost is the normalized host:port of the peer.
// authenticated is true if the peer was verified via signature.
func (pe *PolicyEngine) Evaluate(ctx context.Context, peerHost string, authenticated bool) *PolicyDecision {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	peerHost = strings.ToLower(peerHost)

	// Global enforcement check
	if !pe.cfg.GlobalEnforce {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "policy enforcement disabled",
			ReasonCode:    "policy_disabled",
			Authenticated: authenticated,
		}
	}

	// Denylist always wins
	if pe.isInList(peerHost, pe.cfg.DenyList) {
		pe.logger.Warn("peer denied by denylist", "peer", peerHost)
		return &PolicyDecision{
			Allowed:       false,
			Reason:        "peer in denylist",
			ReasonCode:    "denied_by_denylist",
			Authenticated: authenticated,
		}
	}

	// Allowlist overrides federation membership
	if pe.isInList(peerHost, pe.cfg.AllowList) {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "peer in allowlist",
			ReasonCode:    "allowed_by_allowlist",
			Authenticated: authenticated,
		}
	}

	// Exempt list bypasses federation checks
	if pe.isInList(peerHost, pe.cfg.ExemptList) {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "peer in exempt list",
			ReasonCode:    "allowed_by_exempt",
			Authenticated: authenticated,
		}
	}

	// Check federation membership (M1 union across all federations)
	if pe.federationMgr != nil {
		isMember := pe.federationMgr.IsMember(ctx, peerHost)
		if isMember {
			return &PolicyDecision{
				Allowed:       true,
				Reason:        "peer is federation member",
				ReasonCode:    "allowed_by_federation",
				Authenticated: authenticated,
			}
		}
	}

	// Default: not allowed if not in any list or federation
	return &PolicyDecision{
		Allowed:       false,
		Reason:        "peer not in allowlist or federation",
		ReasonCode:    "not_allowed",
		Authenticated: authenticated,
	}
}

// isInList checks if a host is in a list (case-insensitive).
func (pe *PolicyEngine) isInList(host string, list []string) bool {
	for _, entry := range list {
		if strings.EqualFold(host, entry) {
			return true
		}
	}
	return false
}

// UpdatePolicy updates the policy configuration.
func (pe *PolicyEngine) UpdatePolicy(cfg *PolicyConfig) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.cfg = cfg
}
