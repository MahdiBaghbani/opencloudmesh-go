<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Third-party license notices

This file is a human-readable index of third-party licenses bundled with
OpenCloudMesh Go distributions (Docker image `/app/licenses`, and release
archives when R2 GoReleaser packaging lands).

It does not replace the per-module NOTICE/LICENSE files collected by
`make licenses-save` (`go-licenses save` into `bin/licenses`). Curated
project license texts live under `LICENSES/`.

## How notices are collected

1. `make licenses-save` runs `go-licenses save` for
   `./cmd/opencloudmesh-go` and writes module LICENSE/NOTICE files under
   `bin/licenses` (gitignored).
2. The same target copies this index and the SQLite public-domain
   dedication into that tree so the image build can COPY
   `/build/bin/licenses` to `/app/licenses` in one step.
3. `make licenses-check` enforces the allowlist in
   `.github/licenses-allowlist.txt`. It does not replace reading the
   saved texts.

Release-archive assertion (that this file and `bin/licenses` contents
appear in GoReleaser artifacts) is deferred to R2; this note documents
the intended bundling path only.

## Pure-Go SQLite stack

The server uses a CGO-free SQLite stack. Module LICENSE files for these
packages are collected by `go-licenses`. The original SQLite
public-domain dedication is not copied by go-licenses; it is shipped
separately as `SQLITE-LICENSE` from
`docs/notices/SQLITE-PUBLIC-DOMAIN.txt`.

| Module | Role | License |
| --- | --- | --- |
| `github.com/glebarez/sqlite` | GORM SQLite driver (pure Go) | MIT |
| `github.com/glebarez/go-sqlite` | database/sql driver over modernc | BSD-3-Clause |
| `modernc.org/sqlite` | Pure-Go SQLite translation | BSD-3-Clause |
| `modernc.org/libc` | libc support for modernc SQLite | BSD-3-Clause |
| `modernc.org/mathutil` | math helpers used by modernc | BSD-3-Clause |
| `modernc.org/memory` | memory allocator used by modernc | BSD-3-Clause |

SQLite public-domain dedication:

- SPDX: `LicenseRef-SQLite-Public-Domain`
- REUSE license text: `LICENSES/LicenseRef-SQLite-Public-Domain.txt`
- Curated notice source: `docs/notices/SQLITE-PUBLIC-DOMAIN.txt`
- Bundled name under `bin/licenses` / `/app/licenses`: `SQLITE-LICENSE`

`github.com/glebarez/sqlite` is MIT-licensed.
`github.com/glebarez/go-sqlite` and the `modernc.org/*` translation modules
are BSD-3-Clause. All of their LICENSE files appear under their module
paths in the `go-licenses save` output.

## Other curated license refs

Other project-curated texts under `LICENSES/` (not all are third-party
runtime deps of the server binary):

- `LICENSES/AGPL-3.0-or-later.txt` - project license
- `LICENSES/LicenseRef-IETF-Trust.txt` - IETF Trust terms for vendored
  OCM-API snapshot material
- `LICENSES/LicenseRef-SovereignTech-Brand.txt` - funder brand terms
- `LICENSES/LicenseRef-SQLite-Public-Domain.txt` - SQLite dedication
  (REUSE LicenseRef text; notice source and `SQLITE-LICENSE` bundling
  above)

## Regenerating the machine-collected tree

```sh
make licenses-save
make licenses-check
```

Inspect `bin/licenses` for the full per-module NOTICE/LICENSE set after
`licenses-save`. Keep this index updated when the SQLite stack or other
notable bundled deps change.
