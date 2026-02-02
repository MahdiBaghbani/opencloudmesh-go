package peertrust

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// PolicyDecision represents the result of a policy check.
type PolicyDecision struct {
	Allowed       bool
	Reason        string
	ReasonCode    string
	Authenticated bool // true if peer was authenticated via signature
}

// PolicyEngine evaluates allow/deny and trust group membership.
type PolicyEngine struct {
	cfg           *PolicyConfig
	trustGroupMgr *TrustGroupManager
	logger        *slog.Logger
	mu            sync.RWMutex
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine(cfg *PolicyConfig, trustGroupMgr *TrustGroupManager, logger *slog.Logger) *PolicyEngine {
	logger = logutil.NoopIfNil(logger)
	return &PolicyEngine{
		cfg:           cfg,
		trustGroupMgr: trustGroupMgr,
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

	if !pe.cfg.GlobalEnforce {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "policy enforcement disabled",
			ReasonCode:    "policy_disabled",
			Authenticated: authenticated,
		}
	}

	if pe.isInList(peerHost, pe.cfg.DenyList) {
		pe.logger.Warn("peer denied by denylist", "peer", peerHost)
		return &PolicyDecision{
			Allowed:       false,
			Reason:        "peer in denylist",
			ReasonCode:    "denied_by_denylist",
			Authenticated: authenticated,
		}
	}

	if pe.isInList(peerHost, pe.cfg.AllowList) {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "peer in allowlist",
			ReasonCode:    "allowed_by_allowlist",
			Authenticated: authenticated,
		}
	}

	if pe.isInList(peerHost, pe.cfg.ExemptList) {
		return &PolicyDecision{
			Allowed:       true,
			Reason:        "peer in exempt list",
			ReasonCode:    "allowed_by_exempt",
			Authenticated: authenticated,
		}
	}

	// Check trust group membership (M1 union across all trust groups).
	// When any trust group enforces membership, require verified directory data.
	if pe.trustGroupMgr != nil {
		requireVerified := pe.anyEnforcesMembership()
		isMember := pe.trustGroupMgr.IsMember(ctx, peerHost, requireVerified)
		if isMember {
			return &PolicyDecision{
				Allowed:       true,
				Reason:        "peer is trust group member",
				ReasonCode:    "allowed_by_federation",
				Authenticated: authenticated,
			}
		}
	}

	return &PolicyDecision{
		Allowed:       false,
		Reason:        "peer not in allowlist or trust group",
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

// anyEnforcesMembership returns true if any configured trust group has
// enforce_membership enabled. Conservative: if any does, all membership
// checks require verified directory data.
func (pe *PolicyEngine) anyEnforcesMembership() bool {
	if pe.trustGroupMgr == nil {
		return false
	}
	for _, tg := range pe.trustGroupMgr.GetTrustGroups() {
		if tg.EnforceMembership {
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
