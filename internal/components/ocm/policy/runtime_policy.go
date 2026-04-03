package policy

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// RuntimePolicy holds non-canonical runtime behavior that should not live on
// the canonical OCM policy object.
type RuntimePolicy struct {
	evaluation RuntimeEvaluation
}

type RuntimeTier string

const (
	RuntimeTierStrict RuntimeTier = "strict"
	RuntimeTierCompat RuntimeTier = "compat"
	RuntimeTierDev    RuntimeTier = "dev"
)

type TrustStatus string

const (
	TrustStatusEnforced   TrustStatus = "enforced"
	TrustStatusFeatureOff TrustStatus = "feature-off"
	TrustStatusFailOpen   TrustStatus = "fail-open"
)

type SignaturePosture struct {
	InboundMode                   string
	OutboundMode                  string
	PeerProfileLevelOverride      string
	OnDiscoveryError              string
	RequiresHTTPRequestSignatures bool
	AllowMismatch                 bool
}

type TransportPosture struct {
	SSRFMode           string
	InsecureSkipVerify bool
}

type TrustPosture struct {
	Enabled       bool
	GlobalEnforce bool
	Status        TrustStatus
}

type StrictAssessment struct {
	IsStrict         bool
	ViolationReasons []string
}

type RuntimeEvaluation struct {
	Signature                 SignaturePosture
	DerivedTier               RuntimeTier
	CompatibilityScope        string
	Strict                    StrictAssessment
	Transport                 TransportPosture
	Trust                     TrustPosture
	HasLiveProfileRelaxations bool
}

// NewRuntimePolicy constructs the resolved runtime posture from frozen config.
func NewRuntimePolicy(cfg *config.Config, profileRegistry *peercompat.ProfileRegistry) *RuntimePolicy {
	if cfg == nil {
		return &RuntimePolicy{
			evaluation: RuntimeEvaluation{
				Signature: SignaturePosture{
					InboundMode:              "off",
					OutboundMode:             "off",
					PeerProfileLevelOverride: "off",
					OnDiscoveryError:         "reject",
				},
				DerivedTier:        RuntimeTierCompat,
				CompatibilityScope: "config-unavailable",
				Strict: StrictAssessment{
					IsStrict:         false,
					ViolationReasons: []string{"config_unavailable"},
				},
				Transport: TransportPosture{
					SSRFMode: "strict",
				},
				Trust: TrustPosture{
					Status: TrustStatusFeatureOff,
				},
			},
		}
	}

	signature := SignaturePosture{
		InboundMode:                   cfg.Signature.InboundMode,
		OutboundMode:                  cfg.Signature.OutboundMode,
		PeerProfileLevelOverride:      cfg.Signature.PeerProfileLevelOverride,
		OnDiscoveryError:              cfg.Signature.OnDiscoveryError,
		RequiresHTTPRequestSignatures: deriveHTTPRequestSignatureRequirement(cfg.Signature.InboundMode),
		AllowMismatch:                 cfg.Signature.AllowMismatch,
	}
	transport := TransportPosture{
		SSRFMode:           cfg.OutboundHTTP.SSRFMode,
		InsecureSkipVerify: cfg.OutboundHTTP.InsecureSkipVerify,
	}
	trust := deriveTrustPosture(cfg)
	hasLiveRelaxations := hasMappedProfileRelaxations(cfg, profileRegistry)
	violationReasons := strictAssessmentReasons(signature, transport, trust, hasLiveRelaxations)
	isStrict := len(violationReasons) == 0

	evaluation := RuntimeEvaluation{
		Signature:                 signature,
		DerivedTier:               deriveTier(cfg.Mode, isStrict),
		CompatibilityScope:        deriveCompatibilityScope(cfg, isStrict, hasLiveRelaxations, transport, trust),
		Strict:                    StrictAssessment{IsStrict: isStrict, ViolationReasons: violationReasons},
		Transport:                 transport,
		Trust:                     trust,
		HasLiveProfileRelaxations: hasLiveRelaxations,
	}

	return &RuntimePolicy{evaluation: evaluation}
}

// StrictIncomingSharePayloadValidation reports whether incoming share payload
// validation should use the strict path for the current request.
func (p *RuntimePolicy) StrictIncomingSharePayloadValidation(authenticated bool) bool {
	if p == nil {
		return false
	}
	switch p.evaluation.Signature.InboundMode {
	case "strict":
		return true
	case "lenient":
		return authenticated
	default:
		return false
	}
}

// Evaluate returns the resolved runtime posture snapshot.
func (p *RuntimePolicy) Evaluate() RuntimeEvaluation {
	if p == nil {
		return RuntimeEvaluation{}
	}
	out := p.evaluation
	out.Strict.ViolationReasons = append([]string(nil), p.evaluation.Strict.ViolationReasons...)
	return out
}

func deriveTier(mode string, isStrict bool) RuntimeTier {
	if strings.EqualFold(mode, string(config.ModeDev)) {
		return RuntimeTierDev
	}
	if isStrict {
		return RuntimeTierStrict
	}
	return RuntimeTierCompat
}

func deriveCompatibilityScope(
	cfg *config.Config,
	isStrict bool,
	hasLiveRelaxations bool,
	transport TransportPosture,
	trust TrustPosture,
) string {
	if cfg == nil {
		return "config-unavailable"
	}
	if strings.EqualFold(cfg.Mode, string(config.ModeDev)) {
		return "dev-mode"
	}
	if isStrict {
		return "none"
	}
	if hasLiveRelaxations {
		return "peer-profile-relaxations"
	}
	switch cfg.Signature.OutboundMode {
	case "token-only":
		return "token-only-outbound"
	case "criteria-only":
		return "criteria-only-outbound"
	}
	if cfg.Signature.InboundMode != "strict" ||
		cfg.Signature.OutboundMode != "strict" ||
		cfg.Signature.OnDiscoveryError != "reject" ||
		cfg.Signature.AllowMismatch {
		return "signature-non-strict"
	}
	if transport.SSRFMode != "strict" || transport.InsecureSkipVerify {
		return "transport-relaxed"
	}
	if trust.Status == TrustStatusFailOpen {
		return "peer-trust-fail-open"
	}
	return "compat"
}

func deriveTrustPosture(cfg *config.Config) TrustPosture {
	posture := TrustPosture{
		Enabled:       cfg.PeerTrust.Enabled,
		GlobalEnforce: cfg.PeerTrust.Policy.GlobalEnforce,
		Status:        TrustStatusFeatureOff,
	}
	if !cfg.PeerTrust.Enabled {
		return posture
	}
	if cfg.PeerTrust.Policy.GlobalEnforce {
		posture.Status = TrustStatusEnforced
		return posture
	}
	posture.Status = TrustStatusFailOpen
	return posture
}

func strictAssessmentReasons(
	signature SignaturePosture,
	transport TransportPosture,
	trust TrustPosture,
	hasLiveRelaxations bool,
) []string {
	reasons := make([]string, 0, 8)
	if signature.InboundMode != "strict" {
		reasons = append(reasons, "signature_inbound_mode_not_strict")
	}
	if signature.OutboundMode != "strict" {
		reasons = append(reasons, "signature_outbound_mode_not_strict")
	}
	if signature.PeerProfileLevelOverride != "off" {
		reasons = append(reasons, "signature_peer_profile_override_not_off")
	}
	if signature.OnDiscoveryError != "reject" {
		reasons = append(reasons, "signature_on_discovery_error_not_reject")
	}
	if signature.AllowMismatch {
		reasons = append(reasons, "signature_allow_mismatch_enabled")
	}
	if hasLiveRelaxations {
		reasons = append(reasons, "peer_profile_relaxations_active")
	}
	if transport.SSRFMode != "strict" {
		reasons = append(reasons, "outbound_http_ssrf_mode_not_strict")
	}
	if transport.InsecureSkipVerify {
		reasons = append(reasons, "outbound_http_insecure_skip_verify")
	}
	if trust.Status == TrustStatusFailOpen {
		reasons = append(reasons, "peer_trust_fail_open")
	}
	return reasons
}

func deriveHTTPRequestSignatureRequirement(inboundMode string) bool {
	return strings.EqualFold(inboundMode, "strict")
}

func hasMappedProfileRelaxations(cfg *config.Config, registry *peercompat.ProfileRegistry) bool {
	if cfg.Signature.PeerProfileLevelOverride == "off" {
		return false
	}
	if len(cfg.PeerProfiles.Mappings) == 0 {
		return false
	}
	for _, mapping := range cfg.PeerProfiles.Mappings {
		profile := lookupProfile(mapping.Profile, cfg, registry)
		if profileHasRelaxations(profile) {
			return true
		}
	}
	return false
}

func lookupProfile(
	name string,
	cfg *config.Config,
	registry *peercompat.ProfileRegistry,
) *peercompat.Profile {
	if registry != nil {
		if profile := registry.GetProfileByName(name); profile != nil {
			return profile
		}
	}
	if custom, ok := cfg.PeerProfiles.CustomProfiles[name]; ok {
		return &peercompat.Profile{
			Name:                     name,
			AllowUnsignedInbound:     custom.AllowUnsignedInbound,
			AllowUnsignedOutbound:    custom.AllowUnsignedOutbound,
			AllowMismatchedHost:      custom.AllowMismatchedHost,
			AllowHTTP:                custom.AllowHTTP,
			TokenExchangeQuirks:      custom.TokenExchangeQuirks,
			TokenExchangeGrantType:   "",
			AllowedBasicAuthPatterns: custom.AllowedBasicAuthPatterns,
		}
	}
	return peercompat.BuiltinProfiles()[name]
}

func profileHasRelaxations(profile *peercompat.Profile) bool {
	if profile == nil {
		return false
	}
	if profile.AllowUnsignedInbound || profile.AllowUnsignedOutbound {
		return true
	}
	if profile.AllowMismatchedHost || profile.AllowHTTP {
		return true
	}
	if len(profile.TokenExchangeQuirks) > 0 {
		return true
	}
	if len(profile.AllowedBasicAuthPatterns) > 0 {
		return true
	}
	return profile.TokenExchangeGrantType != "" &&
		profile.TokenExchangeGrantType != "authorization_code"
}
