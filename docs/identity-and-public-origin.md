# Identity and public origin

Every running instance publishes one public identity derived at startup from
`public_origin` and `external_base_path`. That identity drives discovery
URLs, invite sender domains, and route mounting.

## Config inputs

| Field | TOML / CLI | Role |
| ----- | ---------- | ---- |
| `public_origin` | `public_origin`, `-public-origin` | Scheme + host + optional port as seen by clients |
| `external_base_path` | `external_base_path`, `-external-base-path` | Optional path prefix before service mounts |

Example with no base path:

```toml
public_origin = "https://alice.example.com"
external_base_path = ""
```

Discovery `endPoint` becomes `https://alice.example.com/ocm`.

Example behind a path prefix:

```toml
public_origin = "http://fields.test"
external_base_path = "/ocm"
```

Discovery `endPoint` becomes `http://fields.test/ocm/ocm` and WebDAV paths
include the prefix (`/ocm/webdav/ocm/`).

## Derived fields

Package `internal/platform/localidentity` is the single source of truth.

`localidentity.Derive(publicOrigin, externalBasePath)` returns:

| Field | Meaning |
| ----- | ------- |
| `Origin` | Normalized public origin (scheme + host + port) |
| `ProviderDomain` | Published sender/provider domain; default ports stripped |
| `ExternalBasePath` | Validated base path (`""` or `/segment` with no trailing slash) |
| `EndpointBase` | `Origin + ExternalBasePath` |

`localidentity.ValidateExternalBasePath` rejects whitespace, missing leading
slash, trailing slash, `..`, and empty path segments.

## Default-port stripping

`ProviderDomain` uses `hostport.Normalize` with the origin scheme. Standard
ports are omitted from the published domain:

- `https://cloud.example.com:443` -> `cloud.example.com`
- `http://cloud.example.com:80` -> `cloud.example.com`
- Non-default ports are kept: `https://cloud.example.com:8443` ->
  `cloud.example.com:8443`

Alice sends this domain in invite payloads and WAYF redirect query parameters
as `providerDomain`.

## Where identity is consumed

- Discovery document assembly (`internal/services/wellknown`, discovery
  resolve inputs)
- Route full-path computation via `service.RouteOptsFromConfig` and
  `service.Routes`
- Outgoing invite creation and peer comparison

## Verification

```sh
go test ./internal/platform/localidentity/...
go test ./internal/services/wellknown/... -run TestDiscoveryFields
```

Unit proofs:

- `internal/platform/localidentity/localidentity_test.go` -
  `TestDerive_ProviderDomainStripsDefaultPorts`,
  `TestValidateExternalBasePath`
- `internal/services/wellknown/discovery_fields_test.go` -
  `TestDiscoveryFields_DevConfigEmptyBasePath`,
  `TestDiscoveryFields_BasePathMount`
