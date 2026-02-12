## Directory Service (spec) vs /ocm-aux/* (implementation helpers)

This document exists to prevent repeated confusion about "Directory Service" and the `ocmaux` service.

The [OCM-API spec](https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#appendix-c-directory-service) defines a Directory Service (Appendix C) as an optional, third-party input that can be used to facilitate the Invite Flow. Separately, implementations often expose helper endpoints (for example Reva's ScienceMesh endpoints) to power a WAYF (Where Are You From) user experience.

These two things are related, but they are not the same.

### What the spec Directory Service is

The [IETF-RFC spec](https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#appendix-c-directory-service) defines a Directory Service as:

- A third-party back-end service used to federate multiple OCM Servers and facilitate the Invite Flow.
- Exposed via anonymous HTTPS GET.
- Returning a signed JWS (RFC 7515).
- With a payload that includes:
  - `federation` (human-readable federation name)
  - `servers[]` where each entry includes:
    - `url` (absolute URL identifying the OCM Server, with strict constraints)
    - `displayName` (human-readable server name)

Important: The Directory Service is not an OCM Provider endpoint. It is an external input that an implementation may choose to consume.

### What /ocm-aux/federations is (and is not)

`/ocm-aux/federations` is an implementation-defined helper endpoint provided by this server.

It is not the Directory Service.

It may be backed by Directory Service data (for example: aggregating multiple Directory Service URLs, verifying the JWS signatures, and presenting a UI-friendly listing). It may also enrich the listing with additional metadata derived from OCM discovery (for example `inviteAcceptDialog`).

But it is always a local helper surface, not the third-party Directory Service itself.

### What /ocm-aux/discover is (and is not)

`/ocm-aux/discover` is an implementation-defined helper endpoint that runs OCM discovery for a given target and returns derived information. Its purpose is to power UX flows (WAYF) and debugging. It is not part of the canonical OCM Provider protocol endpoints under `/ocm/*`.

### Where invite-accepted trust decisions belong

`POST /ocm/invite-accepted` is an OCM Provider endpoint ([Invite Flow](https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#invite-flow)).

Per the spec, the Invite Sender server should:

- Verify the HTTP message signature.
- Apply its own policy for trusting the Invite Receiver server.
- Return:
  - 200 on success
  - 400 if the invite token is invalid or does not exist
  - 403 if the Invite Receiver server is not trusted to accept the invite
  - 409 if the invite was already accepted

Directory Service data and WAYF helpers may inform the server's trust policy, but the policy decision itself must be enforced in the invite-accepted handler path, not in `/ocm-aux/*`.

### Do not confuse Directory Service JWS with JWKS

- Directory Service uses a signed JWS document whose verification keys are expected to be provisioned out of band (offline).
- JWKS (when present in an implementation) is a key distribution mechanism for HTTP message signatures and is separate from Directory Service.
- OCM discovery `publicKeys[]` is also a key distribution mechanism and is separate from Directory Service.

In other words:

- Directory Service JWS answers "which servers are in this federation list and who vouches for that list?"
- JWKS / discovery keys answer "what keys should I use to verify HTTP message signatures from a given OCM Provider?"
