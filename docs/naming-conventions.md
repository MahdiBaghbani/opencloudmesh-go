# Naming conventions

Naming rules for packages, identifiers, and protocol terms in
opencloudmesh-go. Several rules are enforced by tests in
`internal/architecture/`.

## Packages and directories

- Use lowercase single-word or short compound directory names under
  `internal/components/ocm/` (for example `directoryservice`, not
  abbreviated `ds`).
- HTTP handlers live in `internal/services/<route-group>/`, not mixed into
  component packages.
- Test-only helpers live in `internal/testsupport/<area>/`, never imported
  from production `.go` files.
- Architecture guards live in `internal/architecture/` as `*_test.go` files.

Layering and import boundaries: [architecture.md](architecture.md).

## Directory Service naming

Do not use standalone `DS` or abbreviations like `dsClient`, `dsURL`, or
`DSMember` in production code. Use `directory service` in prose or
`directoryservice` in package paths.

`internal/architecture/naming_conventions_test.go` scans `.go` files for
banned abbreviations (with an exception for the architecture package itself
where the test documents the ban).

Directory Service JSON fields in `internal/components/ocm/directoryservice/`
must follow the OCM spec (for example `url` and `displayName`, not legacy
`domain` or `name` tags). The architecture test
`TestNoNonSpecDirectoryServiceJSONTags` enforces this.

## OCM addresses

Do not parse OCM addresses with naive `strings.SplitN(..., "@", 2)`. Use the
address helpers under `internal/components/ocm/address/`.
`TestNoFirstAtOCMAddressParsing` enforces this under `internal/components/ocm/`.

## Deleted and legacy paths

The `internal/components/federation` package was removed. Do not reintroduce
imports of that path. `TestNoFederationPackageImports` enforces this.

Docs and comments should not refer to removed legacy package names or
old test harness names. If you need federation behavior, use the current
`peer_trust`, `directoryservice`, and `ocmaux` surfaces documented in
[directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md).

## Structured logging

Log keys follow conventions checked by
`internal/architecture/slog_keys_test.go`. Prefer stable, lowercase keys
without redundant prefixes.

## Wire DTOs

Request/response wire types belong in designated locations checked by
`internal/architecture/wire_dto_location_test.go`. Do not place wire DTOs in
arbitrary component packages.

## Test file naming

| Pattern | Location |
| ------- | -------- |
| `*_test.go` | Unit tests next to production code |
| `tests/integration/*_test.go` | Integration scenarios |
| `tests/ca_pool/*_test.go` | CA pool tests |
| `tests/e2e/specs/*.spec.ts` | Playwright browser tests |
| `internal/architecture/*_test.go` | Architecture guard tests |

## Related docs

- [architecture.md](architecture.md) - full guard test catalog
- [repo-layout.md](repo-layout.md) - where packages live
- [testing.md](testing.md) - testsupport import boundary
