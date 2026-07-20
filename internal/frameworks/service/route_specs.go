package service

// SessionPolicy names how the session auth gate treats a route.
type SessionPolicy string

const (
	SessionPublic         SessionPolicy = "public"
	SessionProtected      SessionPolicy = "protected"
	SessionPublicWhenWAYF SessionPolicy = "public when WAYF enabled"
)

// HandlerAuth names handler-level authentication expectations.
type HandlerAuth string

const (
	HandlerAuthNone            HandlerAuth = "none"
	HandlerAuthCurrentUser     HandlerAuth = "current user"
	HandlerAuthRequiredHTTPSig HandlerAuth = "required HTTP signature"
	HandlerAuthBearer          HandlerAuth = "bearer"
	HandlerAuthRateLimitOnly   HandlerAuth = "rate limit only"
)

// SurfaceClass groups routes by product surface.
type SurfaceClass string

const (
	SurfaceDiscovery SurfaceClass = "discovery"
	SurfaceProtocol  SurfaceClass = "protocol"
	SurfaceHelper    SurfaceClass = "helper"
	SurfaceUI        SurfaceClass = "ui"
	SurfaceAPI       SurfaceClass = "api"
	SurfaceWebDAV    SurfaceClass = "webdav"
)

// TrustClass names peer-trust expectations for protocol routes.
type TrustClass string

const (
	TrustPeerNone     TrustClass = "peer-trust-none"
	TrustPeerRequired TrustClass = "peer-trust-required"
)

// FeatureCondition gates a route on optional product features.
type FeatureCondition string

const (
	FeatureNone                FeatureCondition = ""
	FeatureWAYFEnabled         FeatureCondition = "WAYF enabled"
	FeatureInviteAcceptEnabled FeatureCondition = "invite accept enabled"
)

// OutboundProtocolKind records outbound OCM protocol calls triggered by API routes.
type OutboundProtocolKind string

const (
	OutboundNone    OutboundProtocolKind = ""
	OutboundShares  OutboundProtocolKind = "shares"
	OutboundInvites OutboundProtocolKind = "invites"
	OutboundAccess  OutboundProtocolKind = "access"
)

// PeerResolution names which inbound peer resolver an OCM protocol POST route uses.
type PeerResolution string

const (
	PeerResolutionShares         PeerResolution = "shares"
	PeerResolutionInviteAccepted PeerResolution = "invite-accepted"
	PeerResolutionToken          PeerResolution = "token"
)

// OCMProtocolBodyLimitBytes is the pre-verification request body limit for OCM POST routes.
const OCMProtocolBodyLimitBytes int64 = 1 << 20

// RouteSpec is a service-owned route policy declaration. Pattern is relative to
// the service chi router (not the host external_base_path).
type RouteSpec struct {
	ID                   string
	Service              string
	Method               string
	Pattern              string
	SessionPolicy        SessionPolicy
	HandlerAuth          HandlerAuth
	Middleware           []string
	SurfaceClass         SurfaceClass
	DiscoveryFields      []string
	OutboundProtocolKind OutboundProtocolKind
	FeatureCondition     FeatureCondition
	TrustClass           TrustClass
	BodyLimitBytes       int64
	PeerResolution       PeerResolution
}

// RouteOpts carries config-derived values that affect route registration and
// aggregation.
type RouteOpts struct {
	ExternalBasePath    string
	WayfEnabled         bool
	InviteAcceptEnabled bool
	InvitesEnabled      bool
	TokenExchangePath   string
}

// RouteRow is a mounted route with derived full-path metadata. Routes(opts) is
// the canonical aggregate; rows are not authored independently.
type RouteRow struct {
	RouteSpec
	MountAtRoot   bool
	ServicePrefix string
	FullPath      string
	AtHostRoot    bool
	Synthetic     bool
}

// AuthRow is a projection used by the session auth gate.
type AuthRow struct {
	FullPath      string
	SessionPolicy SessionPolicy
	AtHostRoot    bool
	Synthetic     bool
}
