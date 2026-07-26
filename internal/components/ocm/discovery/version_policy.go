package discovery

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// APIVersionMode selects how inbound peer apiVersion values are accepted.
type APIVersionMode uint8

const (
	// APIVersionAcceptAny accepts any non-empty reported apiVersion (default).
	// This is an ocmgo posture choice, not a spec requirement: apiVersion is
	// informative in OCM (https://github.com/cs3org/OCM-API/blob/a5b5da6e17a598266b09a0445db8ac53b29daefc/IETF-OCM.md#L626-L629), so strict-by-default
	// rejection is not required. The accept-any default is intentional and
	// spec-aligned.
	APIVersionAcceptAny APIVersionMode = iota
	// APIVersionExact accepts only apiVersion equal to APIVersionPin.
	// Non-triple strings (for example "1.4" or "1.0-proposal1") are rejected
	// because they are not equal to the pin.
	APIVersionExact
	// APIVersionAtLeast14 accepts valid major.minor.patch triples >= 1.4.0.
	// Non-triple versions are rejected; there is no major-only fallback.
	APIVersionAtLeast14
)

// WarnMode selects when to surface apiVersion mismatch warnings.
type WarnMode uint8

const (
	// WarnAnyDiff warns when reported apiVersion differs from APIVersionPin (default).
	WarnAnyDiff WarnMode = iota
	// WarnLowerOnly warns only when reported parses as a lower comparable triple.
	// Unparseable strings (for example "1.0-proposal1") do not warn because
	// lower cannot be proven.
	WarnLowerOnly
	// WarnNone never warns on apiVersion differences.
	WarnNone
)

// VersionPolicy controls inbound peer apiVersion accept/reject and warnings.
// This is an ocmgo policy axis: apiVersion is informative in OCM, so the
// default accept-any posture is spec-aligned and strict-by-default rejection
// is not required (see the citation on APIVersionAcceptAny above).
// The pin is always APIVersionPin; there is no per-policy Pin field.
type VersionPolicy struct {
	Mode APIVersionMode
	Warn WarnMode
}

// NewVersionPolicy returns the default policy: accept-any with WarnAnyDiff.
// Accept-any is intentional ocmgo posture, not spec-compliance: apiVersion is
// informative in OCM (see the citation on APIVersionAcceptAny).
func NewVersionPolicy() *VersionPolicy {
	return &VersionPolicy{Mode: APIVersionAcceptAny, Warn: WarnAnyDiff}
}

// VersionPolicyFromConfig builds a VersionPolicy from loaded config values.
// Caller must ensure cfg values passed enum validation during config load.
// Defaults are ocmgo posture: accept-any is spec-aligned because apiVersion is
// informative in OCM (see the citation on APIVersionAcceptAny).
func VersionPolicyFromConfig(cfg config.DiscoveryConfig) *VersionPolicy {
	p := NewVersionPolicy()

	switch cfg.PeerAPIVersionPolicy {
	case "exact":
		p.Mode = APIVersionExact
	case "at-least-1.4":
		p.Mode = APIVersionAtLeast14
	default:
		p.Mode = APIVersionAcceptAny
	}

	switch cfg.PeerAPIVersionWarn {
	case "lower-only":
		p.Warn = WarnLowerOnly
	case "none":
		p.Warn = WarnNone
	default:
		p.Warn = WarnAnyDiff
	}

	return p
}

// Accept returns whether reported is acceptable and a warning to surface.
func (p *VersionPolicy) Accept(reported string) (bool, string) {
	if reported == "" {
		return false, ""
	}
	if p == nil {
		p = NewVersionPolicy()
	}

	switch p.Mode {
	case APIVersionExact:
		if reported != spec.APIVersionPin {
			return false, ""
		}
		return true, p.warn(reported)
	case APIVersionAtLeast14:
		if !atLeast14(reported) {
			return false, ""
		}
		return true, p.warn(reported)
	case APIVersionAcceptAny:
		return true, p.warn(reported)
	default:
		return false, ""
	}
}

func (p *VersionPolicy) warn(reported string) string {
	switch p.Warn {
	case WarnNone:
		return ""
	case WarnLowerOnly:
		if cmp, ok := compareDotTriple(reported, spec.APIVersionPin); ok && cmp < 0 {
			return fmt.Sprintf(
				"peer apiVersion %s is lower than pin %s; capability-based consume at operation time, no version handshake",
				reported, spec.APIVersionPin,
			)
		}
		return ""
	case WarnAnyDiff:
		if reported != spec.APIVersionPin {
			return fmt.Sprintf(
				"peer apiVersion %s differs from pin %s; capability-based consume at operation time, no version handshake",
				reported, spec.APIVersionPin,
			)
		}
		return ""
	default:
		return ""
	}
}

// compareDotTriple parses major.minor.patch into ints and compares a against b.
// Returns (cmp, ok); ok is false for unparseable strings (no panic).
func compareDotTriple(a, b string) (int, bool) {
	ma, mi, pa, okA := parseDotTriple(a)
	if !okA {
		return 0, false
	}
	mb, miB, pb, okB := parseDotTriple(b)
	if !okB {
		return 0, false
	}
	if ma != mb {
		if ma < mb {
			return -1, true
		}
		return 1, true
	}
	if mi != miB {
		if mi < miB {
			return -1, true
		}
		return 1, true
	}
	if pa != pb {
		if pa < pb {
			return -1, true
		}
		return 1, true
	}
	return 0, true
}

// atLeast14 accepts valid dot-triple versions >= 1.4.0.
func atLeast14(reported string) bool {
	cmp, ok := compareDotTriple(reported, spec.APIVersionPin)
	return ok && cmp >= 0
}

func parseDotTriple(s string) (major, minor, patch int, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	for _, part := range parts {
		if part == "" {
			return 0, 0, 0, false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, 0, 0, false
			}
		}
	}
	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}
