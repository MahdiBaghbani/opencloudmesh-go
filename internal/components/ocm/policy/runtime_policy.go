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
	TLSMode            string
	SSRFMode           string
	SSRFRoutePolicy    string
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
func NewRuntimePolicy(cfg *config.Config, peerContract *peercompat.CompiledContract) *RuntimePolicy {
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
				CompatibilityScope: "unbounded",
				Strict: StrictAssessment{
					IsStrict:         false,
					ViolationReasons: []string{"config_unavailable"},
				},
				Transport: TransportPosture{
					TLSMode:  "off",
					SSRFMode: "strict",
				},
				Trust: TrustPosture{
					Status: TrustStatusFeatureOff,
				},
			},
		}
	}

	core := NewOpenCloudMeshPolicy(cfg).Evaluate()
	signature := SignaturePosture{
		InboundMode:                   cfg.Signature.InboundMode,
		OutboundMode:                  cfg.Signature.OutboundMode,
		PeerProfileLevelOverride:      cfg.Signature.PeerProfileLevelOverride,
		OnDiscoveryError:              cfg.Signature.OnDiscoveryError,
		RequiresHTTPRequestSignatures: deriveHTTPRequestSignatureRequirement(cfg.Signature.InboundMode),
		AllowMismatch:                 cfg.Signature.AllowMismatch,
	}
	// Mirror the client's own fallback: when the nested SSRF.Mode is empty,
	// consult the SSRFMode shim so programmatic configs that set the top-level
	// field directly are classified consistently.
	ssrfMode := cfg.OutboundHTTP.SSRF.Mode
	if ssrfMode == "" {
		ssrfMode = cfg.OutboundHTTP.SSRFMode
	}
	transport := TransportPosture{
		TLSMode:            cfg.TLS.Mode,
		SSRFMode:           ssrfMode,
		SSRFRoutePolicy:    cfg.OutboundHTTP.SSRF.RoutePolicy,
		InsecureSkipVerify: cfg.OutboundHTTP.InsecureSkipVerify,
	}
	trust := deriveTrustPosture(cfg)
	compatSummary := peercompat.CompatibilitySummary{}
	if peerContract != nil {
		compatSummary = peerContract.Summary()
	}
	hasLiveRelaxations := hasMappedProfileRelaxations(cfg, compatSummary)
	compatibilityScope := configuredCompatibilityScope(cfg)
	violationReasons := strictAssessmentReasons(
		core,
		signature,
		compatibilityScope,
		transport,
		trust,
		hasLiveRelaxations,
	)
	isStrict := len(violationReasons) == 0

	evaluation := RuntimeEvaluation{
		Signature:                 signature,
		DerivedTier:               deriveTier(isStrict, signature, transport, trust),
		CompatibilityScope:        compatibilityScope,
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

// AllowsGlobalCompatibilityDefaults reports whether node-wide compatibility
// defaults may take effect for this runtime posture.
func (p *RuntimePolicy) AllowsGlobalCompatibilityDefaults() bool {
	if p == nil {
		return false
	}
	return p.evaluation.CompatibilityScope == "unbounded"
}

// DirectoryServiceVerificationPolicy reports the default JWS verification
// policy for Directory Service lookups on the trust axis.
func (p *RuntimePolicy) DirectoryServiceVerificationPolicy() string {
	if p != nil && p.AllowsGlobalCompatibilityDefaults() {
		return "optional"
	}
	return "required"
}

func deriveTier(
	isStrict bool,
	signature SignaturePosture,
	transport TransportPosture,
	trust TrustPosture,
) RuntimeTier {
	if isStrict {
		return RuntimeTierStrict
	}
	if hasDevelopmentRelaxations(signature, transport, trust) {
		return RuntimeTierDev
	}
	return RuntimeTierCompat
}

func configuredCompatibilityScope(cfg *config.Config) string {
	if cfg == nil {
		return "unbounded"
	}
	if cfg.CompatibilityScope == "" {
		return "unbounded"
	}
	return cfg.CompatibilityScope
}

func hasDevelopmentRelaxations(
	signature SignaturePosture,
	transport TransportPosture,
	trust TrustPosture,
) bool {
	if transport.TLSMode == "off" ||
		transport.SSRFMode != "strict" ||
		transport.InsecureSkipVerify {
		return true
	}
	if signature.InboundMode == "off" ||
		signature.OutboundMode == "off" ||
		signature.OnDiscoveryError == "allow" ||
		signature.AllowMismatch ||
		signature.PeerProfileLevelOverride == "all" {
		return true
	}
	if trust.Status == TrustStatusFailOpen {
		return true
	}
	return false
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
	core Evaluation,
	signature SignaturePosture,
	compatibilityScope string,
	transport TransportPosture,
	trust TrustPosture,
	hasLiveRelaxations bool,
) []string {
	reasons := make([]string, 0, 8)
	if compatibilityScope != "none" {
		reasons = append(reasons, "compatibility_scope_not_none")
	}
	if !core.TokenExchangeCapable {
		reasons = append(reasons, "ocm_token_exchange_capability_disabled")
	}
	if !core.RequiresTokenExchange {
		reasons = append(reasons, "ocm_require_token_exchange_disabled")
	}
	if !strings.EqualFold(core.PeerPolicy, "strict") {
		reasons = append(reasons, "ocm_peer_policy_not_strict")
	}
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
	if transport.TLSMode == "off" {
		reasons = append(reasons, "tls_mode_off")
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

func hasMappedProfileRelaxations(cfg *config.Config, summary peercompat.CompatibilitySummary) bool {
	if len(cfg.PeerProfiles.Mappings) == 0 {
		return false
	}
	if len(summary.Profiles) == 0 {
		return false
	}
	summaryByName := make(map[string]peercompat.ProfileSummary, len(summary.Profiles))
	for _, profileSummary := range summary.Profiles {
		summaryByName[profileSummary.Name] = profileSummary
	}
	for _, mapping := range cfg.PeerProfiles.Mappings {
		profileSummary, ok := summaryByName[mapping.Profile]
		if !ok {
			continue
		}
		if profileSummary.HasRelaxations {
			return true
		}
	}
	return false
}
