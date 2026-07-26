# Invite, WAYF, and accept

This document covers two invite acceptance paths. Alice always creates the
invite; Bob always accepts on Bob's server. Both sides record accepted state.

- **MVP (API):** Alice creates an invite; Bob imports the invite string and
  accepts via the first-party API.
- **WAYF (browser):** Alice discovers Bob via `/ocm-aux/discover` and is
  redirected to Bob's `/ui/accept-invite` to complete acceptance.

## Roles

- **Alice** (invite sender): creates an outgoing invite and waits for Bob to
  accept.
- **Bob** (invite receiver): imports or lands on an accept URL, accepts the
  invite, and notifies Alice via the OCM protocol.

Accept-invite is always on **Bob's** server (`/ui/accept-invite`). It is not
Alice's public landing page.

## MVP API path (no WAYF browser)

When operators exchange invite strings directly:

1. Alice creates an outgoing invite via `/api/...` (authenticated).
2. Bob imports the invite string via `/api/...` (authenticated).
3. Bob accepts via the first-party API.
4. Bob's server calls `POST /ocm/invite-accepted` on Alice with a signed
   protocol request.
5. Both sides show accepted state.

Proof: `tests/integration/invite_accept_twoinstance_test.go`
(`TestInviteAcceptTwoInstanceAPI`).

```sh
go test ./tests/integration/... -run TestInviteAcceptTwoInstanceAPI
```

## WAYF path (Alice discovers Bob)

When WAYF is enabled (`[http.services.ui.wayf] enabled = true`):

WAYF and the accept-invite UI are independently configured. Set
`[http.services.ui.invite_accept] enabled = true` to enable the
`/ui/accept-invite` route and invite discovery fields. This setting is
independent of WAYF; configure both for the complete WAYF path.

1. Alice creates an outgoing invite (same as above).
2. Alice's browser or client calls `/ocm-aux/discover?base=<bob-url>` on
   Alice's server. The helper normalizes pasted URLs (bare host, deep file
   paths) to a provider origin, runs OCM discovery against Bob, and returns
   `inviteAcceptDialogAbsolute`.
3. Alice redirects the user to Bob's accept-invite URL with query parameters
   `token` (invite token) and `providerDomain` (Alice's published domain).
4. Bob's `/ui/accept-invite` requires a session. Unauthenticated requests
   get `302` to `/ui/login?redirect=<encoded accept path with query>`.
5. After login, Bob imports and accepts via API (same as MVP API path).
6. Bob notifies Alice via `POST /ocm/invite-accepted`.

### Alice/Bob example

Alice at `https://alice.test`, Bob at `https://bob.test`:

```text
Alice creates invite token T, providerDomain alice.test
Alice GET https://alice.test/ocm-aux/discover?base=https://bob.test
  -> inviteAcceptDialogAbsolute https://bob.test/ui/accept-invite
Redirect user to:
  https://bob.test/ui/accept-invite?token=T&providerDomain=alice.test
Bob (unauthenticated) GET that URL -> 302 /ui/login?redirect=...
Bob logs in, accepts via API, Alice outgoing status becomes accepted
```

Proof: `tests/integration/wayf_invite_accept_test.go`
(`TestWayfInviteAcceptTwoInstance`).

Browser proof: `tests/e2e/specs/wayf.spec.ts`,
`tests/e2e/specs/wayf-two-instance.spec.ts`.

```sh
go test ./tests/integration/... -run TestWayfInviteAcceptTwoInstance
make test-e2e   # includes wayf specs
```

## Protected accept-invite with state preservation

The accept-invite route uses `SessionProtected` policy. Query parameters
(`token`, `providerDomain`) must survive the login redirect:

- Unauthenticated `GET /ui/accept-invite?...` returns `302` with
  `Location: /ui/login?redirect=<full accept path including query>`
- Login page renders with the same `redirect` query parameter
- After successful login the UI returns to the exact accept URL

Proof: `tests/integration/accept_invite_redirect_test.go`
(`TestAcceptInviteRedirectRoundTrip`).

```sh
go test ./tests/integration/... -run TestAcceptInviteRedirect
```

## inviteAcceptDialog: local vs inbound

| Direction | Behavior |
| --------- | -------- |
| Local discovery publish | Absolute URL derived from mounted `/ui/accept-invite` |
| Inbound peer discovery | Relative paths tolerated and normalized to absolute |
| `/ocm-aux/discover` helper | Adds `inviteAcceptDialogAbsolute` for WAYF consumers |

Route policy keeps `inviteAcceptDialog` on the UI accept route, not on
`POST /ocm/invite-accepted`. Proof:
`internal/architecture/route_policy_wiring_test.go`
(`TestRoutePolicyWiring_InviteAcceptDialogDistinctFromInviteAccepted`).

## Verification split

Two integration tracks cover different parts of the invite story:

### Manual discover normalization before WAYF

Subprocess tests prove `/ocm-aux/discover` accepts operator-pasted input
(bare hostname, deep paths), blocks SSRF targets with friendly errors, and
requires `inviteAcceptDialog` on the target peer.

- `tests/integration/ocmaux_discover_normalization_test.go`

```sh
go test ./tests/integration/... -run TestOCMAuxDiscover
```

### Hermetic Directory Service JWS after MVP acceptance

Separate from WAYF discover normalization: a signed Directory Service listing
feeds `/ocm-aux/federations` with per-row discovery enrichment. This path
uses hermetic HTTPS JWS fixtures, not live third-party directory operators.

- `tests/integration/directoryservice_federations_test.go`

```sh
go test ./tests/integration/... -run TestDirectoryServiceJWSFeedsFederations
```

See [directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md) for
how Directory Service relates to `/ocm-aux/*`.

## Related docs

- [discovery.md](discovery.md) - discovery field derivation
- [protocol-endpoints.md](protocol-endpoints.md) - `POST /ocm/invite-accepted`
- [routes-and-auth.md](routes-and-auth.md) - WAYF feature gates and session policy
