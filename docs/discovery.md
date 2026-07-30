<!-- markdownlint-disable MD024 -->
# Discovery

The provider discovery document at `/.well-known/ocm` advertises capabilities,
endpoints, and invite UX metadata. Fields are derived from local identity,
route specs, and runtime policy -- not hand-edited per request.

## Core document fields

Built by `internal/components/ocm/discovery` and served by
`internal/services/wellknown`. Typical fields:

| Field | Source |
| ----- | ------ |
| `enabled`, `apiVersion`, `provider` | Handler and spec pin (`apiVersion` advertises `1.4.0`; inbound peers are accepted per `[ocm.discovery]` policy) |
| `endPoint` | Route-derived projection from local identity |
| `tokenEndPoint` | Projected when token exchange is capable |
| `resourceTypes[].protocols` | `webdav` path plus `webdav-receive` with `uri: relative` |
| `capabilities` | `http-sig` when JWKS signing keys are published, `exchange-token` when token exchange is capable, `invites` when `InvitesEnabled` is true (defaults true; OCM invite protocol routes are always mounted), `invite-wayf` only when the WAYF route is enabled |
| `criteria` | Strictness requirements (HTTP sig, token exchange, denylist/allowlist when configured) |
| `inviteAcceptDialog` | Derived when invite accept route is active |

With `external_base_path = "/ocm"` on origin `http://fields.test`:

- `endPoint`: `http://fields.test/ocm/ocm`
- `tokenEndPoint`: `http://fields.test/ocm/ocm/token`
- WebDAV protocol path: `/ocm/webdav/ocm/`

## Route-linked discovery fields

Route specs declare `DiscoveryFields` on UI routes:

- `/ui/wayf` drives capability `invite-wayf` when `RouteOpts.WayfEnabled` is true
- `/ui/accept-invite` advertises `inviteAcceptDialog`

When the invite accept route is active, the wellknown handler derives an
**absolute** local `inviteAcceptDialog` URL from the mounted accept-invite
path. Explicit config or raw provider JSON can override auto-derivation.

At the builder and route-spec level, `inviteAcceptDialog` and `invite-wayf`
are independent: each field follows its own route spec or explicit config
override, so a handler can advertise accept without WAYF when only the
accept-invite route is active.

WAYF is off by default (`[http.services.ui.wayf] enabled = false`). The
`invite-wayf` capability and `/ui/wayf` route register only when that
section is enabled. Invite accept UI routes and `inviteAcceptDialog`
follow `[http.services.ui.invite_accept] enabled` independently of WAYF.
The `invites` capability follows `RouteOpts.InvitesEnabled`, which
defaults true. See [routes-and-auth.md](routes-and-auth.md).

Proof: `internal/services/wellknown/ocm_handler_test.go`
(`TestNewOCMHandler_InviteAcceptDialogFromRoutes`) and
`internal/components/ocm/discovery/builder_test.go`
(`TestBuildDiscovery_InviteAcceptIndependentFromWAYF`).

## Discovery subset

ocmgo advertises a deliberate subset of the OCM discovery document. It is a
WebDAV-centered OCM implementation, not a full OCM server. Field sources and
route-linked behavior are described in
[Core document fields](#core-document-fields);
this section maps what ocmgo publishes against the full OCM-API enumerations.

The IANA OCM Parameters registry group is authoritative for these parameter
enumerations ([OCM-API registry overview][iana-ocm-params]). The five
registries are: OCM Resource Types, OCM Protocols, OCM Share Types, OCM Share
Payloads, and OCM Notification Types.

[iana-ocm-params]: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1801-L1809

### Capabilities (4 of 7)

Full OCM capability enumeration (7 total):
[OCM-API capabilities][ocm-capabilities].

| Capability | ocmgo |
| ---------- | ----- |
| `http-sig` | advertised |
| `exchange-token` | advertised |
| `invites` | advertised |
| `invite-wayf` | advertised when WAYF route is enabled |
| `enforce-mfa` | omitted |
| `notifications` | omitted |
| `protocol-object` | omitted |

[ocm-capabilities]: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L709-L738

### Criteria (up to 4 of 5)

Full OCM criteria enumeration (5 total):
[OCM-API criteria][ocm-criteria].

| Criterion | ocmgo |
| --------- | ----- |
| `must-use-http-sig` | advertised when HTTP signatures are required |
| `must-exchange-token` | advertised when token exchange is required |
| `denylist` | advertised when `[peer_trust] enabled` is true and `[peer_trust.policy] deny_list` is nonempty |
| `allowlist` | advertised when `[peer_trust] enabled` is true and `[peer_trust.policy] allow_list` is nonempty |
| `must-invite` | omitted (not yet enforced) |

[ocm-criteria]: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L739-L764

### Host normalization

Trust-group membership uses `hostport.Normalize` (lowercase, default-port
stripping, IPv6 bracket preservation) through
`internal/platform/hostport/hostport.go`. Denylist/allowlist matching is
case-insensitive comparison only (lowercased `peerHost` versus list entries
using `strings.EqualFold`); list entries are not passed through
`hostport.Normalize`.

This behavior is an ocmgo implementation choice. The OCM specification defines
`denylist` and `allowlist` criteria as IP-address based and does not define
FQDN matching ([IETF-OCM.md:759-762][ocm-criteria-ip]).

[ocm-criteria-ip]: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L759-L762

### Protocol roles (WebDAV send, one receive)

Full OCM protocol role pairs (3 sending/receiving pairs):
[OCM-API protocol roles][ocm-protocol-roles].

| Role | ocmgo |
| ---- | ----- |
| `webdav` (send) | advertised |
| `webdav-receive` | advertised |
| `webapp` (send) | omitted |
| `webapp-receive` | omitted (deliberately removed; inbound webapp shares return 501 because ocmgo does not advertise `webapp-receive`) |
| `ssh` (send) | omitted |
| `ssh-receive` | omitted |

[ocm-protocol-roles]: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L669-L708

Built by `internal/components/ocm/discovery/builder.go`.

## Inbound peer discovery

When this server discovers a remote peer (`internal/components/ocm/discovery`
client), the client validates the document before returning it:

- `apiVersion` is checked against `[ocm.discovery]` policy (default:
  accept-any with any-diff warning). Operators may select exact,
  at-least-1.4, or accept-any; warnings are configurable (any-diff,
  lower-only, none). Capability-based consume happens at operation time; there
  is no version handshake.
- `endPoint` and `tokenEndPoint` (when present) must be absolute URLs on the
  same authority as the discovered peer origin
- `exchange-token` capability and `tokenEndPoint` must appear together
- `webdav` and `webdav-receive` protocol roles must use supported value shapes
- Other protocol roles (for example `talk`, `webapp`, `ssh`, or custom roles)
  are preserved opaquely with a warning, not rejected

Relative `inviteAcceptDialog` values from the peer document are normalized to
absolute URLs, then rejected when the resolved authority does not match the
peer origin. This same-authority binding is an SSRF-defense product choice for
outbound discovery consumption, not a protocol spec MUST.

Proof: `internal/components/ocm/discovery/client_test.go`.

## OCM-API prose vs schema

The pinned OCM-API describes `inviteAcceptDialog` as a URL. Real peers often
send a relative path. This server:

- Publishes an absolute URL locally (derived from routes)
- Accepts relative inbound values, resolves them against the discovered peer
  origin, and fails closed on cross-authority results

The helper `/ocm-aux/discover` adds `inviteAcceptDialogAbsolute` in its JSON
response so WAYF UI code always receives a ready-to-navigate URL even when
the raw discovery field was relative.

## Config that affects discovery

| Config | Effect |
| ------ | ------ |
| `public_origin`, `external_base_path` | All endpoint and WebDAV paths |
| `[token_exchange]` | Token endpoint and `exchange-token` capability |
| Signature and peer trust axes | Criteria and capabilities |
| `[http.services.ui.wayf] enabled` | `invite-wayf` capability and WAYF UI route |
| `[http.services.ui.invite_accept] enabled` | Accept-invite UI route and `inviteAcceptDialog` |
| `[ocm.discovery] peer_api_version_policy` | Inbound peer apiVersion accept policy |
| `[ocm.discovery] peer_api_version_warn` | Inbound peer apiVersion warning mode |

Unknown keys under `[http.services.wellknown.ocmprovider]` fail at load time.

## Verification

```sh
go test ./internal/services/wellknown/... -run 'DiscoveryFields|InviteAcceptDialogFromRoutes|InviteWAYFCapability|TruthfulCapabilitySet'
go test ./internal/components/ocm/discovery/...
go test ./tests/integration/... -run 'DiscoveryEndpoint|DiscoveryRemains|DiscoveryRoutesMatch'
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
