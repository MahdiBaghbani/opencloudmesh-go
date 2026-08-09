<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Reproducible builds

A build is reproducible when the same source code, build environment, and
build instructions produce byte-identical artifacts on any machine. This
document records how opencloudmesh-go achieves that and how to verify it.

## What makes the build reproducible

The release binary is built with flags that remove sources of variation:

- `-trimpath` strips absolute build paths from the binary, so the build
  directory and checkout location do not leak into the output.
- `-s -w` strips the symbol table and debug info, which can otherwise carry
  environment-specific data.
- `CGO_ENABLED=0` produces a pure-Go static binary, so a local C toolchain
  cannot vary the output.
- `main.version` is stamped from git (`git describe --tags --always --dirty`),
  which is deterministic for a given commit.
- The Go toolchain is pinned by the `go` directive in `go.mod`, so the same
  source builds with the same compiler.

The goreleaser config (`.goreleaser.yaml`) sets `mod_timestamp:
"{{ .CommitTimestamp }}"` on the build and `info.mtime: "{{ .CommitDate }}"` on
the bundled notice and license files. This pins the modification time of every
file inside the release archive to the commit time, so the archive is
byte-identical regardless of when or where it is built.

## Verify locally

Run the reproduce target, which builds the binary twice into separate output
paths and compares their SHA-256 digests:

```sh
make reproduce
```

On success it prints the shared digest twice and `reproduce: OK (bit-for-bit
identical)`. On a mismatch it exits non-zero, which means the build is not
reproducible and should be investigated before releasing.

## Verify a release archive

Every release produced by goreleaser ships a `checksums.txt` file with the
SHA-256 digest of each artifact. To verify a downloaded archive against it:

```sh
sha256sum -c checksums.txt --ignore-missing
```

The digest is stable across rebuilds of the same tag because the archive
contents (binary and bundled files) and their mtimes are pinned as described
above.
