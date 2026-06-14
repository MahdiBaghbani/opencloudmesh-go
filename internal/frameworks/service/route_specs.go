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
	HandlerAuthOptionalHTTPSig HandlerAuth = "optional HTTP signature"
	HandlerAuthRequiredHTTPSig HandlerAuth = "required HTTP signature"
	HandlerAuthBearerOrBasic   HandlerAuth = "bearer or basic"
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
	TrustPeerNone             TrustClass = "peer-trust-none"
	TrustPeerRequired         TrustClass = "peer-trust-required"
	TrustNotificationsSpecial TrustClass = "notifications-special"
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
	OutboundNone          OutboundProtocolKind = ""
	OutboundNotifications OutboundProtocolKind = "notifications"
	OutboundShares        OutboundProtocolKind = "shares"
	OutboundInvites       OutboundProtocolKind = "invites"
	OutboundTokenExchange OutboundProtocolKind = "token-exchange"
	OutboundAccess        OutboundProtocolKind = "access"
)

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
}

// RouteOpts carries config-derived values that affect route registration and
// aggregation. MVP sources InviteAcceptEnabled from the same WAYF config flag.
type RouteOpts struct {
	ExternalBasePath    string
	WayfEnabled         bool
	InviteAcceptEnabled bool
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
