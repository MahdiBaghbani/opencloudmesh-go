// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

// SessionPolicy names how the session auth gate treats a route.
type SessionPolicy string

const (
	// SessionPublic is the public session policy.
	SessionPublic SessionPolicy = "public"
	// SessionProtected is the protected session policy.
	SessionProtected SessionPolicy = "protected"
	// SessionPublicWhenWAYF is the public-when-WAYF session policy.
	SessionPublicWhenWAYF SessionPolicy = "public when WAYF enabled"
)

// HandlerAuth names handler-level authentication expectations.
type HandlerAuth string

const (
	// HandlerAuthNone is the no-authentication handler policy.
	HandlerAuthNone HandlerAuth = "none"
	// HandlerAuthCurrentUser is the current-user handler policy.
	HandlerAuthCurrentUser HandlerAuth = "current user"
	// HandlerAuthRequiredHTTPSig is the required HTTP signature handler policy.
	HandlerAuthRequiredHTTPSig HandlerAuth = "required HTTP signature"
	// HandlerAuthBearer is the bearer-token handler policy.
	HandlerAuthBearer HandlerAuth = "bearer"
	// HandlerAuthRateLimitOnly is the rate-limit-only handler policy.
	HandlerAuthRateLimitOnly HandlerAuth = "rate limit only"
)

// SurfaceClass groups routes by product surface.
type SurfaceClass string

const (
	// SurfaceDiscovery is the discovery route surface class.
	SurfaceDiscovery SurfaceClass = "discovery"
	// SurfaceProtocol is the protocol route surface class.
	SurfaceProtocol SurfaceClass = "protocol"
	// SurfaceHelper is the helper route surface class.
	SurfaceHelper SurfaceClass = "helper"
	// SurfaceUI is the UI route surface class.
	SurfaceUI SurfaceClass = "ui"
	// SurfaceAPI is the API route surface class.
	SurfaceAPI SurfaceClass = "api"
	// SurfaceWebDAV is the WebDAV route surface class.
	SurfaceWebDAV SurfaceClass = "webdav"
)

// TrustClass names peer-trust expectations for protocol routes.
type TrustClass string

const (
	// TrustPeerNone is the no-peer-trust policy.
	TrustPeerNone TrustClass = "peer-trust-none"
	// TrustPeerRequired is the required peer trust policy.
	TrustPeerRequired TrustClass = "peer-trust-required"
)

// FeatureCondition gates a route on optional product features.
type FeatureCondition string

const (
	// FeatureNone is the empty feature condition.
	FeatureNone FeatureCondition = ""
	// FeatureWAYFEnabled gates routes on WAYF being enabled.
	FeatureWAYFEnabled FeatureCondition = "WAYF enabled"
	// FeatureInviteAcceptEnabled gates routes on invite accept being enabled.
	FeatureInviteAcceptEnabled FeatureCondition = "invite accept enabled"
	// FeatureValidatorEnabled gates routes on federation validator being enabled.
	FeatureValidatorEnabled FeatureCondition = "validator enabled"
)

// OutboundProtocolKind records outbound OCM protocol calls triggered by API routes.
type OutboundProtocolKind string

const (
	// OutboundNone is the empty outbound protocol kind.
	OutboundNone OutboundProtocolKind = ""
	// OutboundShares is the shares outbound protocol kind.
	OutboundShares OutboundProtocolKind = "shares"
	// OutboundInvites is the invites outbound protocol kind.
	OutboundInvites OutboundProtocolKind = "invites"
	// OutboundAccess is the access outbound protocol kind.
	OutboundAccess OutboundProtocolKind = "access"
)

// PeerResolution names which inbound peer resolver an OCM protocol POST route uses.
type PeerResolution string

const (
	// PeerResolutionShares is the shares peer resolution strategy.
	PeerResolutionShares PeerResolution = "shares"
	// PeerResolutionInviteAccepted is the invite-accepted peer resolution strategy.
	PeerResolutionInviteAccepted PeerResolution = "invite-accepted"
	// PeerResolutionToken is the token peer resolution strategy.
	PeerResolutionToken PeerResolution = "token"
	// PeerResolutionNotifications is the notifications peer resolution strategy.
	PeerResolutionNotifications PeerResolution = "notifications"
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
	ValidatorEnabled    bool
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
	MatchExact    bool
}

// AuthRow is a projection used by the session auth gate.
type AuthRow struct {
	FullPath      string
	SessionPolicy SessionPolicy
	AtHostRoot    bool
	Synthetic     bool
}
