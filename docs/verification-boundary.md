# Verification boundary

This repo verifies a narrow strict contract. A green strict run does not
claim broad peer compatibility. It proves the behaviors listed here and
leaves broader interoperability to explicit compatibility configuration
and operator-managed validation.

## What this repo does prove

- `compatibility_scope=none` is the no-exceptions lane. It forbids
  `peer_profiles.mappings` and peer-scoped relaxations, and it requires
  the strict signature, transport, token-exchange, and trust settings
  that keep the runtime inside the current WebDAV-centered strict
  target.
- The transport axis uses a nested SSRF subsystem. The strict preset is
  deny-by-default there: `ssrf.mode=strict`, no active route policy, and
  no private-route exceptions unless an operator-declared transport
  allowlist is configured.
- Private-route exceptions stay narrow. They require an active route
  policy, and transport allowlisting stays separate from peer
  compatibility.
- A strict route policy does not by itself demote the runtime to dev
  posture. Under `compatibility_scope=none`, strict SSRF plus a named
  route policy can still resolve to the strict tier. Under broader
  compatibility scope, the non-strict result comes from the compatibility
  axis, not from the route policy itself.
- `ssrf.mode=off` is a real transport relaxation. It is outside the
  strict posture and remains distinct from peer-compatibility settings.
- In that lane, outbound signing stays strict across endpoint kinds.
  Token exchange does not get a special outbound-signing exception when
  `compatibility_scope=none` is in effect.
- Inbound verification rejects malformed HTTP-signature material. The
  verified behavior is strict rejection, not degraded acceptance.
- Discovery caching stores raw response bytes and re-normalizes on cache
  read. The cache therefore preserves the fetched source bytes while
  letting the current peer contract control how legacy discovery fields
  are interpreted.
- Outbound proxy behavior is intentionally split:
  - `proxy_url` is an explicit operator choice and takes precedence over
    environment fallback.
  - `proxy_env_fallback` reads `HTTP_PROXY`, `HTTPS_PROXY`, and
    `NO_PROXY` only when `proxy_url` is not set.
  - Under `compatibility_scope=none`, the proxy host is treated as an
    operator-trusted hop, so private and loopback proxy addresses are
    allowed.
  - Destination SSRF checks remain the hard boundary. Proxy routing and
    `NO_PROXY` can change how a request is sent, but they do not permit
    blocked destinations.

## What this repo does not prove

- A green strict run here does not claim broad interoperability with
  arbitrary peers.
- Peer-specific relaxations, compatibility mappings, and deployment-specific
  behavior remain outside the strict contract of this repo.
- External end-to-end or wire-level interoperability suites may still be
  useful as downstream proof surfaces, but they are not the product contract
  of `opencloudmesh-go`.

## What remains operator-gated

Broader peer compatibility, peer-specific relaxations, and containerized
proof remain explicit operator choices.

This repo does not automatically build, tag, or publish a container
image as part of strict verification. Using a container image as part of
downstream proof is operator-managed.
