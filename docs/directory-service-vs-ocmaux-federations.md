# Directory Service (spec) vs /ocm-aux/* (implementation helpers)

This document exists to prevent repeated confusion about "Directory Service"
and the `ocmaux` service.

The [OCM-API spec][ocm-appendix-c-directory-service] defines a Directory
Service (Appendix C) as an optional, third-party input that can be used to
facilitate the Invite Flow. Separately, this server exposes local helper
endpoints under `/ocm-aux/*` (for example `/ocm-aux/federations` and
`/ocm-aux/discover`) to power a WAYF (Where Are You From) user experience.

These surfaces are related, but they are not the same:

- **Directory Service** is a third-party HTTPS GET that returns a signed JWS
  federation listing. It is not OCM discovery and it is not JWKS.
- **`/ocm-aux/federations`** is a local helper that may read cached Directory
  Service listings and enrich each provider row with OCM discovery metadata.
- **`/ocm-aux/discover`** is a local helper that runs OCM discovery for one
  target URL and returns derived UX information.
- **Invite trust** is enforced in OCM protocol handlers (for example
  `POST /ocm/invite-accepted`), not in `/ocm-aux/*`.

[ocm-appendix-c-directory-service]: https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#appendix-c-directory-service

## What the spec Directory Service is

The [IETF-RFC spec][ocm-appendix-c-directory-service] defines a Directory
Service as:

- A third-party back-end service used to federate multiple OCM Servers and
  facilitate the Invite Flow.
- Exposed via anonymous HTTPS GET.
- Returning a signed JWS (RFC 7515).
- With a payload that includes:
  - `federation` (human-readable federation name)
  - `servers[]` where each entry includes:
    - `url` (absolute URL identifying the OCM Server, with strict constraints)
    - `displayName` (human-readable server name)

Important: The Directory Service is not an OCM Provider endpoint, not OCM
discovery, and not JWKS. It is an external input that an implementation may
choose to consume.

## What /ocm-aux/federations is (and is not)

`/ocm-aux/federations` is an implementation-defined helper endpoint provided
by this server. Route specs tag it with `SurfaceClass: helper`
(`SurfaceHelper`).

It is not the Directory Service.

It is a local provider-list endpoint. It reads cached Directory Service
listings (JWS fetch, signature verification, and cache refresh happen
elsewhere), merges them into a UI-friendly federation listing, and may
enrich each server row by calling OCM discovery for that row's `url`.

Enrichment behavior:

- On success, the row may include `inviteAcceptDialog` (when discovery reports
  one). The row omits `status`.
- On discovery failure, the row is **retained** (not dropped). The response
  includes a `status` object with canonical outcome fields only:

```json
{
  "discovery": "failed",
  "reasonCode": "<canonical reason>"
}
```

`reasonCode` uses the same canonical codes as other peer/discovery surfaces
(for example `peer_discovery_failed`, `peer_unreachable`). Debug details
(including the underlying error) stay in server logs; the helper response must
not include raw internal error text.

But it is always a local helper surface, not the third-party Directory Service
itself.

## What /ocm-aux/discover is (and is not)

`/ocm-aux/discover` is an implementation-defined helper endpoint that runs OCM
discovery for a given target and returns derived information. Route specs tag
it with `SurfaceClass: helper` (`SurfaceHelper`).

Its purpose is to power UX flows (WAYF) and debugging for a single provider
base URL. It is not part of the canonical OCM Provider protocol endpoints
under `/ocm/*`, and it is not the Directory Service.

Use `/ocm-aux/discover` when you need discovery output for one target. Use
`/ocm-aux/federations` when you need a federation/provider listing that may
already combine Directory Service data with per-row discovery enrichment.

## Where invite-accepted trust decisions belong

`POST /ocm/invite-accepted` is an OCM Provider endpoint
([Invite Flow][ocm-invite-flow]).

Per the spec, the Invite Sender server should:

- Verify the HTTP message signature.
- Apply its own policy for trusting the Invite Receiver server.
- Return:
  - 200 on success
  - 400 if the invite token is invalid or does not exist
  - 403 if the Invite Receiver server is not trusted to accept the invite
  - 409 if the invite was already accepted

Directory Service data and WAYF helpers may inform the server's trust policy,
but the policy decision itself must be enforced in the invite-accepted handler
path, not in `/ocm-aux/*`.

[ocm-invite-flow]: https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#invite-flow

## Do not confuse Directory Service JWS with JWKS or OCM discovery

- Directory Service uses a signed JWS document whose verification keys are
  expected to be provisioned out of band (offline).
- JWKS (when present in an implementation) is a key distribution mechanism for
  HTTP message signatures and is separate from Directory Service.
- OCM discovery `publicKeys[]` is also a key distribution mechanism and is
  separate from Directory Service.
- OCM discovery against a provider's `url` is a separate step from fetching a
  Directory Service listing. `/ocm-aux/federations` may perform discovery
  enrichment after consuming a listing, but that does not make the Directory
  Service itself "discovery".

In other words:

- Directory Service JWS answers "which servers are in this federation list and
  who vouches for that list?"
- JWKS / discovery keys answer "what keys should I use to verify HTTP message
  signatures from a given OCM Provider?"
- OCM discovery answers "what capabilities and UX metadata does this provider
  expose?"
