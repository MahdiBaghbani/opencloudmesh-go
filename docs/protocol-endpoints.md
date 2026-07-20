# Protocol endpoints

OCM provider protocol traffic lives under the `ocm` service mount. These
endpoints implement the pinned OCM-API subset for shares, invite
acceptance, and the strict authorization-code flow. Helper, UI, and
first-party API routes are documented separately.

## Mount shape

With empty `external_base_path`, protocol handlers mount at `/ocm/*`. With
`external_base_path = "/myapp"`, the same patterns mount at
`/myapp/ocm/*`.

Full paths come from `service.Routes(opts)`; see
[routes-and-auth.md](routes-and-auth.md).

## Endpoint categories

Protocol traffic uses `SurfaceClass: protocol`, public session policy, and
required HTTP signature handler auth. Peer trust is enforced per route.

The `ocm` service registers three protocol handlers in
`internal/services/ocm/routes.go`. Route ids, patterns, and trust metadata
aggregate through `service.Routes(opts)` in
`internal/frameworks/service/route_aggregate.go`. Projections such as
`service.DerivedRouteInventory` derive from that aggregate. This page
explains behavior; it is not a maintained route list. See
[routes-and-auth.md](routes-and-auth.md).

`internal/architecture/route_policy_wiring_test.go` locks wiring expectations:

- `TestRoutePolicyProjections_DerivedFromRoutes` - projections match
  `Routes(opts)`
- `TestRoutePolicyWiring_HTTPsigHandlerAuthOnlyOnOCMProtocol` - HTTP
  signature handler auth only on protocol routes
- `TestRoutePolicyWiring_ProtocolRoutesHavePeerTrustClass` - peer trust on
  every protocol route
- `TestRoutePolicyWiring_InviteAcceptDialogDistinctFromInviteAccepted` -
  `/ui/accept-invite` is not `POST /ocm/invite-accepted`

### Shares

`POST /ocm/shares` receives incoming share creation from a remote OCM
provider. The accepted share grammar is:

- Required fields: `shareWith`, `name`, `providerId`, `owner`, `sender`,
  `shareType`, `resourceType`, and `protocol`
- `shareType`: `user`
- `resourceType`: `file` or `folder`
- `protocol.name`: `multi` or `webdav`
- `protocol.webdav`: `uri`, `sharedSecret`, `permissions: ["read"]`, and
  `requirements: ["must-exchange-token"]`
- `protocol.webdav.accessTypes`: `["remote"]` when present; omission also
  means remote access

Optional share display fields and expiration remain part of the wire model.
Additional protocol arms and values outside this grammar are rejected.

### Invite accepted

`POST /ocm/invite-accepted` is the OCM protocol callback when Bob's server
accepts Alice's invite. Trust and signature verification happen here, not on
UI or helper routes.

This endpoint must not be confused with `/ui/accept-invite`, which is Bob's
local landing page for humans. See
[invite-wayf-and-accept.md](invite-wayf-and-accept.md).

### Token exchange

`POST /ocm/<token_exchange.path>` handles the strict authorization-code
exchange when the configured code-flow capability is active. Requests use
`grant_type=authorization_code`, `client_id`, and `code`; successful
responses contain a Bearer access token. The default path segment is `token`;
override it with `[token_exchange] path` or `-token-exchange-path`.

## What is not protocol

| Surface | Example prefix | Purpose |
| ------- | -------------- | ------- |
| Discovery | `/.well-known/ocm` | Provider capability document |
| Helper | `/ocm-aux/discover`, `/ocm-aux/federations` | WAYF UX and operator helpers |
| UI | `/ui/wayf`, `/ui/accept-invite` | Browser pages |
| API | `/api/*` | First-party JSON for the bundled UI |
| WebDAV | `/webdav/ocm/*` | File access for accepted shares |

Architecture tests enforce that HTTP signature handler auth and peer trust
classes appear only on protocol routes under the `ocm` service.

## Verification

```sh
go test ./internal/architecture/... -run RoutePolicy
go test ./internal/services/ocm/...
go test ./tests/integration/... -run InviteAccept
```

Integration proofs:

- `tests/integration/invite_accept_twoinstance_test.go` -
  `TestInviteAcceptTwoInstanceAPI` (MVP API path through
  `POST /ocm/invite-accepted`)
- `tests/integration/wayf_invite_accept_test.go` -
  `TestWayfInviteAcceptTwoInstance` (WAYF plus accept-invite redirect)
