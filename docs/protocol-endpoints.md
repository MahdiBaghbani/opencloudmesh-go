# Protocol endpoints

OCM provider protocol traffic lives under the `ocm` service mount. These
endpoints implement the pinned OCM-API subset for shares, notifications,
invites, and token exchange. Helper, UI, and first-party API routes are
documented separately.

## Mount shape

With empty `external_base_path`, protocol handlers mount at `/ocm/*`. With
`external_base_path = "/myapp"`, the same patterns mount at
`/myapp/ocm/*`.

Full paths come from `service.Routes(opts)`; see
[routes-and-auth.md](routes-and-auth.md).

## Endpoint categories

All protocol routes use `SurfaceClass: protocol`, public session policy, and
optional HTTP signature handler auth. Trust is enforced per route.

| Route id | Method | Pattern | Trust |
| -------- | ------ | ------- | ----- |
| `ocm-shares` | POST | `/shares` | Peer required |
| `ocm-notifications` | POST | `/notifications` | Notifications special |
| `ocm-invite-accepted` | POST | `/invite-accepted` | Peer required |
| `ocm-token` | POST | configurable (default `/token`) | Peer required |

Registration: `internal/services/ocm/routes.go`.

### Shares

`POST /ocm/shares` receives incoming share creation from a remote OCM
provider. Handler auth expects an optional HTTP message signature when
configured.

### Notifications

`POST /ocm/notifications` receives asynchronous notifications (for example
share state changes). Uses a notifications-specific trust class.

### Invite accepted

`POST /ocm/invite-accepted` is the OCM protocol callback when Bob's server
accepts Alice's invite. Trust and signature verification happen here, not on
UI or helper routes.

This endpoint must not be confused with `/ui/accept-invite`, which is Bob's
local landing page for humans. See
[invite-wayf-and-accept.md](invite-wayf-and-accept.md).

### Token exchange

`POST /ocm/<token_exchange.path>` handles token exchange when enabled.
Default path segment is `token`; override via `[token_exchange] path` or
`-token-exchange-path`.

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
