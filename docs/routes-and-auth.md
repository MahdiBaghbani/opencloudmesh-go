# Routes and auth

HTTP routes are declared once per service package and aggregated centrally.
This document explains how route policy is derived and how auth surfaces
differ. It is not a route inventory.

## Service-owned route specs

Each HTTP service registers `RouteSpec` values from its `routes.go` file
(for example `internal/services/ocm/routes.go`,
`internal/services/ui/routes.go`). A spec names:

- HTTP method and pattern (relative to the service chi router)
- `SessionPolicy` (public, protected, or public when WAYF enabled)
- `HandlerAuth` (none, session user, HTTP signature, bearer/basic, rate limit)
- `SurfaceClass` (discovery, protocol, helper, ui, api, webdav)
- `TrustClass` for protocol routes (peer trust required or none)
- Optional `DiscoveryFields`, `FeatureCondition`, and
  `OutboundProtocolKind`

Specs register through `service.RegisterRouteSpecs` at package init time.

## Canonical aggregate: Routes(opts)

`service.Routes(opts)` in `internal/frameworks/service/route_aggregate.go`
is the sole canonical route-policy aggregate. It:

1. Collects active specs via `RegisteredRouteSpecs(opts)` (honoring feature
   gates such as WAYF and invite accept)
2. Computes each row's `FullPath` from the service descriptor, optional
   `external_base_path`, and pattern
3. Appends synthetic subtree rows for coarse session policy on `/api/*`,
   `/ui/*`, and similar prefixes

`RouteOpts` carries config-derived inputs:

- `ExternalBasePath`
- `WayfEnabled` from `[http.services.ui.wayf] enabled`
- `InviteAcceptEnabled` from `[http.services.ui.invite_accept] enabled`
- `InvitesEnabled` defaults true (OCM invite protocol routes are always mounted)
- `TokenExchangePath`

Build opts with `service.RouteOptsFromConfig(cfg)`.

## Route-policy projections

These functions derive policy views from the same `Routes(opts)` rows:

| Function | Purpose |
| -------- | ------- |
| `DerivedAuthRows` | Session auth rows for middleware |
| `DerivedRouteGroups` | Coarse mount subtrees and auth requirement |
| `DerivedRouteInventory` | Active product routes (non-synthetic) |
| `SessionAuthRequiredForPath` | Hot-path lookup (via `SessionAuthChecker`) |

Architecture tests assert projections stay consistent with `Routes(opts)` and
that metadata is complete on every product route.

## Surface classes

Routes group into product surfaces:

| Surface | Typical services | Session / handler auth |
| ------- | ---------------- | ---------------------- |
| Discovery | `wellknown` | Public; no session |
| Protocol | `ocm` | Public session; optional HTTP signature on handler |
| Helper | `ocmaux` | Public; rate limit on discover |
| UI | `ui` | Mix of public login/WAYF and protected inbox |
| API | `api` | Protected first-party session |
| WebDAV | `webdav` | Public session; bearer or basic on handler |

Protocol routes (`SurfaceProtocol`) require peer trust classes and are the
only routes that use HTTP signature handler auth. Helper and UI routes use
`TrustPeerNone` and never use HTTP signature handler auth.

## Feature gates

WAYF UI routes register only when `[http.services.ui.wayf] enabled = true` in
config. Invite accept UI routes and discovery fields independently use
`[http.services.ui.invite_accept] enabled = true`.

Token exchange path comes from `[token_exchange] path` (default `token`).

## Verification

```sh
go test ./internal/architecture/... -run RoutePolicy
go test ./internal/frameworks/service/... -run Route
```

Key proofs:

- `internal/architecture/route_policy_wiring_test.go` - projections match
  `Routes`, HTTP signature only on protocol routes, invite accept dialog
  distinct from `POST /ocm/invite-accepted`
- `internal/frameworks/service/route_specs_test.go` - registered specs,
  WAYF session policy, `RouteOptsFromConfig` branches

See also [protocol-endpoints.md](protocol-endpoints.md) and
[discovery.md](discovery.md) for how route specs feed discovery fields.
