package resolve

import (
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
)

// RequestPeerIdentity resolves the request-scoped peer domain used by the
// matched-peer gate. An empty return value fails closed for apiVersion overrides.
type RequestPeerIdentity func(r *http.Request) string

func filterAPIVersionOverrides(
	raw []APIVersionOverride,
	contract *peercompat.CompiledContract,
) []APIVersionOverride {
	if contract == nil || len(raw) == 0 {
		return nil
	}

	out := make([]APIVersionOverride, 0, len(raw))
	for _, override := range raw {
		if !overrideBindingValid(override, contract) {
			continue
		}
		out = append(out, override)
	}
	return out
}

func overrideBindingValid(
	override APIVersionOverride,
	contract *peercompat.CompiledContract,
) bool {
	if strings.TrimSpace(override.Profile) == "" {
		return false
	}
	if strings.TrimSpace(override.APIVersion) == "" {
		return false
	}
	if strings.TrimSpace(override.UserAgentContains) == "" {
		return false
	}
	if contract == nil {
		return false
	}
	_, ok := contract.ProfileByName(override.Profile)
	return ok
}

// SelectAPIVersionOverride returns an override apiVersion only when the request
// peer matches a configured profile through the compiled contract and the
// User-Agent predicate also matches.
func SelectAPIVersionOverride(
	overrides []APIVersionOverride,
	contract *peercompat.CompiledContract,
	peerInput string,
	userAgent string,
) (string, bool) {
	if len(overrides) == 0 || contract == nil {
		return "", false
	}

	peer := strings.TrimSpace(peerInput)
	if peer == "" {
		return "", false
	}

	decision := contract.SignatureDecisionForPeer(peer)
	if !decision.Matched {
		return "", false
	}

	for _, override := range overrides {
		if override.Profile != decision.Profile {
			continue
		}
		if !strings.Contains(userAgent, override.UserAgentContains) {
			continue
		}
		return override.APIVersion, true
	}

	return "", false
}
