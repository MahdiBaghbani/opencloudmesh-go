# Verification boundary

This repo verifies a narrow strict contract. A green strict run does not
claim broad peer interoperability. It proves the behaviors listed here and
leaves broader interoperability to operator-managed validation.

## What this repo does prove

- The strict lane requires the strict signature, transport, token-exchange,
  and trust settings that keep the runtime inside the current
  WebDAV-centered strict target.
- The transport axis uses a nested SSRF subsystem. The strict preset is
  deny-by-default there: `ssrf.mode=strict`, no active route policy, and
  no private-route exceptions unless an operator-declared route policy is
  configured.
- Private-route exceptions stay narrow. They require an active route
  policy, and the verified positive path is an operator-declared
  host-suffix/CIDR/port allowlist for matching private hostname
  destinations only. Under an active SSRF route policy,
  `allow_ip_literals=true` is rejected at config load, so IP-literal
  targets stay forbidden in the strict lane. Transport allowlisting stays
  separate from peer identity.
- The explicit-CIDR integration proof is intentionally narrow: it covers a
  matching operator-declared allowlist and the paired blocked case
  without that allowance. It does not prove arbitrary private-network
  interoperability.
- A strict route policy does not by itself demote the runtime to dev
  posture. Strict SSRF plus a named route policy can still resolve to the
  strict tier.
- `ssrf.mode=off` is a real transport relaxation. It is outside the
  strict posture and remains distinct from the signing and trust settings.
- In that lane, outbound signing stays strict across endpoint kinds,
  including token exchange.
- Inbound verification rejects malformed HTTP-signature material. The
  verified behavior is strict rejection, not degraded acceptance.
- Strict inbound mode does **not** mean Ed25519-only peers. Default
  `signature.allowed_algorithms` accepts asymmetric
  [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) algorithms
  `ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`, and
  `rsa-v1_5-sha256` / `rsa-v1_5-sha384` / `rsa-v1_5-sha512`. Symmetric
  algorithms remain forbidden.
- Outbound SignRequest uses the same allow-list: the local signing key
  algorithm must be listed in `signature.allowed_algorithms` or signing
  fails before the request is sent (default key remains Ed25519).
- Signature-Input `alg` may be omitted when the peer JWKS determines the
  algorithm ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)). If `alg`
  is present, it must agree with the JWK-derived algorithm; disagreement is
  rejected. ECDSA P-256 verification is covered by an
  [RFC 9421 Appendix B.2.4](https://www.rfc-editor.org/rfc/rfc9421.html#section-B.2.4)
  vector and by an end-to-end path
  through JWKS, peer discovery, and inbound middleware when `alg` is omitted.
- Remote JWKS fetch rejects a nil HTTP client and responses larger than
  `DefaultMaxResponseBytes` (`ErrResponseTooLarge`; no silent truncate).
  Documents are cached briefly (default 1m TTL). Forced refetch on kid miss
  respects `minRefetchInterval` (default 30s). Concurrent fetches for the
  same URL are singleflighted. Kid misses may be negative-cached briefly.
- Inbound signature failure responses use coarse bodies. Reason-to-body
  and status mapping:
  - `key_not_found` -> HTTP 401 `signature key not found`
  - `key_lookup_failed` -> HTTP 502 `signature key lookup failed`
  - `algorithm_rejected` -> HTTP 401 `signature algorithm rejected`
  - all other verify failures (`malformed`, `missing_created`,
    `future_created`, `stale_created`, `missing_component`,
    `crypto_fail`, ...) -> HTTP 401 `signature verification failed`
  Details remain in logs.
- When a declared-peer resolver is present, malformed or empty declared
  peers fail closed with HTTP 400. Shares, invite-accepted, and token
  routes require a declared peer (`requireDeclaredPeer`).
- Peer identity mismatch between declared peer and keyId authority
  returns HTTP 403. Normalize errors on that path also fail closed with
  403.
- Discovery caching stores raw response bytes and re-normalizes on cache
  read. The cache preserves the fetched source bytes while applying current
  discovery normalization on cache reads.
- Outbound proxy behavior is intentionally split:
  - `proxy_url` is an explicit operator choice and takes precedence over
    environment fallback.
  - `use_env_fallback` is an explicit opt-in knob. In the strict preset it
    defaults to false. Set `use_env_fallback = true` in TOML or
    `OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true` to opt in. When
    enabled and `proxy_url` is not set, outbound HTTP reads
    `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.
  - `OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK` is currently the only
    supported environment override; it overrides the `use_env_fallback`
    TOML key, and the environment layer is the highest precedence (above
    preset default, TOML, and CLI flags where they exist;
    `use_env_fallback` has no CLI flag).
  - Under the strict lane, the proxy host is treated as an operator-trusted
    hop, so private and loopback proxy addresses are allowed.
- Destination SSRF checks remain the hard boundary. Proxy routing and
  `NO_PROXY` can change how a request is sent, but they do not permit
  blocked destinations.

See [outbound-http-ssrf.md](outbound-http-ssrf.md) for discover helper
behavior and operator-facing error shapes.

## What this repo does not prove

- A green strict run here does not claim broad interoperability with
  arbitrary peers.
- Deployment-specific behavior remains outside the strict contract of this
  repo.
- External end-to-end or wire-level interoperability suites may still be
  useful as downstream proof surfaces, but they are not the product contract
  of `opencloudmesh-go`.

## What remains operator-gated

Broader peer interoperability and containerized proof remain explicit
operator choices.

This repo does not automatically build, tag, or publish a container
image as part of strict verification. Using a container image as part of
downstream proof is operator-managed.
