# Discovery

The provider discovery document at `/.well-known/ocm` advertises capabilities,
endpoints, and invite UX metadata. Fields are derived from local identity,
route specs, and runtime policy -- not hand-edited per request.

## Core document fields

Built by `internal/components/ocm/discovery` and served by
`internal/services/wellknown`. Typical fields:

| Field | Source |
| ----- | ------ |
| `enabled`, `apiVersion`, `provider` | Handler and spec pin |
| `endPoint` | Local identity + OCM mount (`EndpointBase` + `/ocm`) |
| `tokenEndPoint` | Projected when token exchange is capable |
| `resourceTypes[].protocols.webdav` | WebDAV route wildcard projection |
| `capabilities` | Policy flags (invites, webdav-uri, notifications, ...). Adds `invite-wayf` when the WAYF route is active. |
| `criteria` | Strictness requirements (HTTP sig, token exchange) |
| `publicKeys` | Signing keys when configured |
| `inviteAcceptDialog` | Derived when invite accept route is active |

With `external_base_path = "/ocm"` on origin `http://fields.test`:

- `endPoint`: `http://fields.test/ocm/ocm`
- `tokenEndPoint`: `http://fields.test/ocm/ocm/token`
- WebDAV protocol path: `/ocm/webdav/ocm/`

## Route-linked discovery fields

Route specs declare `DiscoveryFields` on UI routes:

- `/ui/wayf` advertises capability `invite-wayf`
- `/ui/accept-invite` advertises `inviteAcceptDialog`

When the invite accept route is active, the wellknown handler derives an
**absolute** local `inviteAcceptDialog` URL from the mounted accept-invite
path. Explicit config or raw provider JSON can override auto-derivation.

At the builder and route-spec level, `inviteAcceptDialog` and `invite-wayf`
are independent: each field follows its own route spec or explicit config
override, so a handler can advertise accept without WAYF when only the
accept-invite route is active.

WAYF is off by default (`[http.services.ui.wayf] enabled = false`). When
you set `enabled = true`, the default config wiring registers WAYF and
accept-invite UI routes and their discovery fields together. See
[routes-and-auth.md](routes-and-auth.md).

Proof: `internal/services/wellknown/ocm_handler_test.go`
(`TestNewOCMHandler_InviteAcceptDialogFromRoutes`) and
`internal/components/ocm/discovery/builder_test.go`
(`TestBuildDiscovery_InviteAcceptIndependentFromWAYF`).

## Inbound peer discovery

When this server discovers a remote peer (`internal/components/ocm/discovery`
client), relative `inviteAcceptDialog` values from the peer document are
normalized to absolute URLs:

- `/apps/ocm/invite-accept` against `https://peer.example.com` ->
  `https://peer.example.com/apps/ocm/invite-accept`
- `apps/ocm/invite-accept` (no leading slash) is also accepted

Proof: `internal/components/ocm/discovery/client_test.go`
(`TestClientDiscover_NormalizesRelativeInviteAcceptDialog`,
`TestClientDiscover_NormalizesRelativeInviteAcceptDialogWithoutEndPoint`).

## OCM-API prose vs schema

The pinned OCM-API describes `inviteAcceptDialog` as a URL. Real peers often
send a relative path. This server:

- Publishes an absolute URL locally (derived from routes)
- Accepts relative inbound values and resolves them against the discovered
  peer origin

The helper `/ocm-aux/discover` adds `inviteAcceptDialogAbsolute` in its JSON
response so WAYF UI code always receives a ready-to-navigate URL even when
the raw discovery field was relative.

## Config that affects discovery

| Config | Effect |
| ------ | ------ |
| `public_origin`, `external_base_path` | All endpoint and WebDAV paths |
| `[token_exchange]` | Token endpoint and `exchange-token` capability |
| Signature / peer policy axes | Criteria and capabilities |
| `[http.services.ui.wayf] enabled` | WAYF capability and accept-invite route |

## Verification

```sh
go test ./internal/services/wellknown/... -run 'DiscoveryFields|InviteAcceptDialogFromRoutes|InviteWAYFCapability|UnconditionalCapabilities'
go test ./internal/components/ocm/discovery/...
go test ./tests/integration/... -run 'DiscoveryEndpoint|LegacyDiscovery|DiscoveryRemains|DiscoveryRoutesMatch'
```

- `internal/services/wellknown/discovery_fields_test.go` - endpoint and
  WebDAV projection with and without base path
- `internal/services/wellknown/ocm_handler_test.go` - route-linked
  `inviteAcceptDialog` and capability derivation from handler routes
- `tests/integration/health_test.go` - live discovery JSON and endpoint
  placement from a running server
- `tests/integration/discovery_routes_test.go` - route-linked discovery
  fields from a running server
- `internal/components/ocmaux/handler_discover_contract_test.go` -
  `inviteAcceptDialogAbsolute` helper output
