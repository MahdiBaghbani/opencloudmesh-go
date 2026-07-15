# Directory Service and OCM aux

Two different surfaces often get conflated: the OCM-API Directory Service
(Appendix C) and this server's local `/ocm-aux/*` helpers. They work
together in WAYF flows but serve different roles.

## Directory Service (spec)

The [OCM-API Directory Service][ocm-ds] is an optional third-party HTTPS GET
that returns a signed JWS (RFC 7515) listing federation members:

- `federation` - human-readable name
- `servers[]` with `url` and `displayName`

It is not OCM discovery, not JWKS, and not an OCM provider endpoint.
Verification keys are provisioned out of band.

[ocm-ds]: https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1#appendix-c-directory-service

This server consumes Directory Service listings through
`internal/components/ocm/directoryservice` when configured under
`[peer_trust]` trust groups.

## /ocm-aux/federations (local helper)

`GET /ocm-aux/federations` is a **local** helper (`SurfaceClass: helper`).
It is not the Directory Service itself.

Behavior:

1. Read cached Directory Service JWS listings (fetch, verify, refresh happen
   in the directoryservice client)
2. Merge verified listings into a UI-friendly federation array
3. Optionally enrich each server row by calling OCM discovery for that row's
   `url`

Enrichment outcomes:

- Success: row may include `inviteAcceptDialog` from peer discovery; no
  `status` field
- Discovery failure: row is **retained** with a canonical `status` object:

```json
{
  "discovery": "failed",
  "reasonCode": "peer_discovery_failed"
}
```

Raw internal errors stay in server logs, not in the JSON response.

Registration: `internal/services/ocmaux/routes.go` (`ocmaux-federations`).

## /ocm-aux/discover (local helper)

`GET /ocm-aux/discover?base=<url>` runs OCM discovery for one target and
returns UX-oriented JSON including `inviteAcceptDialogAbsolute`. Used for
manual provider entry in WAYF before redirecting to a peer's accept-invite
page.

Registration: `internal/services/ocmaux/routes.go` (`ocmaux-discover`).

See [invite-wayf-and-accept.md](invite-wayf-and-accept.md) for the Alice/Bob
WAYF sequence and [outbound-http-ssrf.md](outbound-http-ssrf.md) for SSRF
behavior on discover outbound calls.

## Trust decisions stay on protocol routes

`POST /ocm/invite-accepted` enforces invite trust and HTTP signatures.
Directory Service data and `/ocm-aux/*` helpers may inform policy, but they
do not replace protocol handler checks.

## Do not confuse JWS with JWKS or discovery keys

| Mechanism | Question it answers |
| --------- | ------------------- |
| Directory Service JWS | Which servers are in a federation list and who vouches for it? |
| JWKS / discovery `publicKeys` | Which keys verify HTTP message signatures from a provider? |
| OCM discovery | What capabilities and UX metadata does a provider expose? |

Fetching a Directory Service listing is separate from discovering a provider's
`/.well-known/ocm`. `/ocm-aux/federations` may call discovery per row after
consuming a listing; that enrichment does not make the Directory Service
endpoint "discovery".

## Config

Directory Service endpoints and verification keys live under `[peer_trust]`
trust group JSON (see `internal/components/ocm/directoryservice` types).
Enable peer trust and point `config_paths` at trust group files.

Example integration fixture pattern:
`tests/integration/directoryservice_federations_test.go`.

## Verification

### Hermetic Directory Service JWS (T7b)

```sh
go test ./tests/integration/... -run TestDirectoryServiceJWSFeedsFederations
go test ./internal/components/ocm/directoryservice/...
```

### Federations helper unit tests

```sh
go test ./internal/components/ocmaux/... -run Federations
```

Unit proofs include `internal/components/ocm/directoryservice/client_jws_test.go`
and `internal/components/ocmaux/handler_federations_test.go`.

## Related docs

- [invite-wayf-and-accept.md](invite-wayf-and-accept.md) - WAYF and T7a/T7b
  verification split
- [discovery.md](discovery.md) - OCM discovery fields
- [routes-and-auth.md](routes-and-auth.md) - helper surface class
