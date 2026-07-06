# Docker

This page covers building and running OpenCloudMesh Go as a container,
including the full environment-variable reference. For the day-to-day local
workflow without Docker, see [development.md](development.md).

## Build

```sh
./scripts/build-docker.sh
# or: docker build -t opencloudmesh-go:local -f docker/Dockerfile .
```

## Run

HTTP mode (default, port 8080):

```sh
docker run -d -p 8080:8080 -e HOST=ocm-go1 opencloudmesh-go:local
curl http://localhost:8080/.well-known/ocm
```

TLS mode with the pre-installed certs (port 443):

```sh
docker run -d -p 443:443 -e HOST=ocm-go1 -e TLS_ENABLED=true opencloudmesh-go:local
curl -k https://localhost/.well-known/ocm
```

Custom config, mounted into the container:

```sh
docker run -d -p 8080:8080 \
  -v /path/to/config.toml:/configs/config.toml:ro \
  -e CONFIG=/configs/config.toml -e HOST=ocm-go1 \
  opencloudmesh-go:local
```

## How the entrypoint resolves identity

The container needs a public origin. It is resolved in this order:

1. If `PUBLIC_ORIGIN` is set, it is used as-is.
2. Otherwise `HOST` is used to derive one:
   - TLS mode: `https://<HOST>.docker`
   - HTTP mode: `http://<HOST>.docker:8080`
3. If neither is set, startup fails.

When `HOST` is set, `127.0.0.1 <HOST>.docker` is added to `/etc/hosts` so the
instance can reach itself by its published name. If no `CONFIG` is given, the
entrypoint selects `/configs/config-tls.toml` in TLS mode or
`/configs/config.toml` otherwise. The server logs to
`/var/log/opencloudmesh-go.log`.

## Environment variables

Identity (set at least one of `HOST` or `PUBLIC_ORIGIN`):

| Variable      | Required               | Description |
| ------------- | ---------------------- | ----------- |
| HOST          | If PUBLIC_ORIGIN empty | Short hostname such as `ocm-go1`. Added to `/etc/hosts` and used to derive the public origin. |
| PUBLIC_ORIGIN | If HOST empty          | Full base URL. Passed to the server as `--public-origin`. |

Mode:

| Variable    | Default | Description |
| ----------- | ------- | ----------- |
| OCM_GO_MODE | (none)  | Override the preset bundle: `strict`, `compat`, or `dev`. |

Config:

| Variable | Default | Description |
| -------- | ------- | ----------- |
| CONFIG   | (auto)  | Path to a config file in the container. Defaults to the bundled TLS or HTTP config depending on `TLS_ENABLED`. |

TLS:

| Variable    | Default | Description |
| ----------- | ------- | ----------- |
| TLS_ENABLED | false   | Set to `true` to serve TLS on port 443. |
| TLS_CERT    | (none)  | Base64-encoded PEM cert. Overwrites the pre-installed leaf cert at startup. |
| TLS_KEY     | (none)  | Base64-encoded PEM key. Overwrites the pre-installed key at startup. |
| TLS_CA      | (none)  | Base64-encoded PEM CA. Overwrites the pre-installed CA and updates the trust store. |

## Pre-installed TLS material

| File                   | Purpose |
| ---------------------- | ------- |
| ocm-go.crt, ocm-go.key | Leaf certificate and key |
| dockypody.crt          | CA added to the trust store |

Pre-installed cert hostnames: `ocm-go.docker`, `ocm-go1.docker` through
`ocm-go4.docker`, `localhost`, `127.0.0.1`, `::1`.
