# opencloudmesh-go

Open Cloud Mesh (OCM) server implementation in Go. Delivered as the M5 (OCM
Stub Implementation) milestone of the [Sovereign Tech
Fund](https://github.com/orgs/cs3org/projects/3/views/1) funded OCM project.

## Purpose

This project provides an Open Cloud Mesh server implementation in Go. The
current strict target is a practical WebDAV-centered subset of the pinned
OCM-API surface: latest-shape discovery, `shareType=user`, the current
notification subset, and strict token-exchange and HTTP-signature behavior on
that reduced path.

The runtime exposes preset bundles `strict`, `compat`, and `dev`. The legacy
alias `interop` is still accepted for `compat`.

Those presets are convenience entry points, not the architecture authority:
the effective posture is resolved from canonical OCM policy,
`compatibility_scope`, and the signature, transport, trust, and peer-compat
axes.

`compatibility_scope` is the supervising exception-governance axis:
`none` means no compatibility relaxations, `scoped` allows explicit peer-scoped
exceptions, and `unbounded` allows node-wide compatibility defaults. A strict
runtime posture is derived only when the resolved behavior stays inside the
WebDAV-centered strict target and `compatibility_scope=none`.

Verification boundaries for the strict target are documented in
[`docs/verification-boundary.md`](docs/verification-boundary.md).

`token-only` is an outbound-only HTTP-signature relaxation. It is useful for
compatibility, but it is never part of the strict posture.

## OCM-STA and Milestones

Project tasks and milestones are coordinated in the [OCM-STA repository](https://github.com/cs3org/OCM-STA). OCM-STA holds Sovereign Tech Fund activity tracking. M5 (OCM Stub Implementation) is delivered by this repo.

## Build and test

```sh
# Build
make build

# Unit and integration tests (excludes E2E)
make test

# E2E tests (requires make test-e2e-install once)
make test-e2e
```

## Docker

Build and run the server in a container.

| Mode  | Port | Description                                                  |
| ----- | ---- | ------------------------------------------------------------ |
| HTTP  | 8080 | Default. No TLS.                                             |
| TLS   | 443  | Set TLS_ENABLED=true. Uses pre-installed or env-provided certs. |

| Pre-installed files     | Purpose            |
| ----------------------- | ------------------ |
| ocm-go.crt, ocm-go.key  | Leaf cert and key  |
| dockypody.crt           | CA for trust store |

Pre-installed cert hostnames: ocm-go.docker, ocm-go1.docker through ocm-go4.docker, localhost, 127.0.0.1, ::1

```sh
# Build
./scripts/build-docker.sh
# or: docker build -t opencloudmesh-go:local -f docker/Dockerfile .

# HTTP mode (default)
docker run -d -p 8080:8080 -e HOST=ocm-go1 opencloudmesh-go:local
curl http://localhost:8080/.well-known/ocm

# TLS mode (pre-installed certs)
docker run -d -p 443:443 -e HOST=ocm-go1 -e TLS_ENABLED=true opencloudmesh-go:local
curl -k https://localhost/.well-known/ocm

# Custom config (mount your config and set CONFIG path)
docker run -d -p 8080:8080 -v /path/to/config.toml:/config/config.toml:ro \
  -e CONFIG=/config/config.toml -e HOST=ocm-go1 opencloudmesh-go:local
```

### Environment variables

**Identity (set at least one of HOST or PUBLIC_ORIGIN):**

| Variable      | Required               | Description                                                               |
| ------------- | ---------------------- | -------------------------------------------------------------------------- |
| HOST          | If PUBLIC_ORIGIN empty | Short hostname (e.g. ocm-go1). Added to /etc/hosts. Used to derive PUBLIC_ORIGIN. |
| PUBLIC_ORIGIN | If HOST empty          | Full base URL. Passed as --public-origin.                                  |

**Mode:**

| Variable    | Default | Description                                   |
| ----------- | ------- | --------------------------------------------- |
| OCM_GO_MODE | (none)  | Override preset bundle: `strict`, `compat`, or `dev`. The legacy alias `interop` is also accepted. |

**Config:**

| Variable | Default | Description                                                             |
| -------- | ------- | ----------------------------------------------------------------------- |
| CONFIG   | (auto)  | Path to config.toml in container. Use with `-v` to mount your own file. |

**TLS:**

| Variable    | Default | Description                                                         |
| ----------- | ------- | ------------------------------------------------------------------- |
| TLS_ENABLED | false   | Set to `true` for TLS on port 443.                                  |
| TLS_CERT    | (none)  | Base64-encoded PEM cert. Overwrites pre-installed cert at startup.  |
| TLS_KEY     | (none)  | Base64-encoded PEM key. Overwrites pre-installed key at startup.   |
| TLS_CA      | (none)  | Base64-encoded PEM CA. Overwrites pre-installed CA and updates trust store. |

## OCM-API specification

Protocol behavior is defined in the [OCM-API IETF-RFC](https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#ocm-api-discovery).
