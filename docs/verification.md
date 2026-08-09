<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Verifying a release

Release artifacts are built reproducibly (see
[reproducible-builds.md](reproducible-builds.md)) and signed with Sigstore
cosign keyless signing in the release workflow. Each release archive and the
`checksums.txt` manifest carry a `.sigstore.json` bundle that lets you verify
both integrity and provenance.

You need the `cosign` tool (`cosign verify-blob`) and `sha256sum`.

## 1. Verify the checksum manifest

The `checksums.txt` file lists the SHA-256 digest of every archive. First
confirm the archive you downloaded matches the manifest:

```sh
sha256sum -c checksums.txt --ignore-missing
```

Then verify that `checksums.txt` itself was signed by the release workflow
(Sigstore keyless, issued by GitHub Actions OIDC):

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/MahdiBaghbani/opencloudmesh-go/.github/workflows/release-binary.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

A successful verification prints the certificate identity and issuer and
exits zero.

## 2. Verify an archive directly

Each archive also ships its own `.sigstore.json` bundle, so you can verify a
single archive without trusting `checksums.txt`:

```sh
cosign verify-blob \
  --bundle opencloudmesh-go_<version>_linux_amd64.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/MahdiBaghbani/opencloudmesh-go/.github/workflows/release-binary.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  opencloudmesh-go_<version>_linux_amd64.tar.gz
```

Replace `<version>` and the OS/arch archive name with the file you downloaded.

## What you are proving

- **Integrity:** the archive bytes match the recorded signature and the
  SHA-256 in `checksums.txt`.
- **Provenance:** the signature was produced by a workflow run on
  `MahdiBaghbani/opencloudmesh-go`'s `release-binary.yml`, authenticated by
  GitHub Actions OIDC and logged to the public Rekor transparency log. No
  long-lived signing key is held by any individual.

GitHub also records a build-provenance attestation for each artifact in the
GitHub Attestations API; the cosign bundles above are the release-asset form
that the OpenSSF Scorecard signed-releases check recognizes.

## 3. Verify the release tag

The release tag itself is cryptographically signed with gitsign keyless
(Sigstore) in the release workflow, so you can confirm a tag was created by
the project's release workflow and not forged.

Check the tag's signature:

```sh
git tag -v <version>
```

For a gitsign-signed tag, `git tag -v` reports a valid CMS/X.509 signature.
To inspect the signing certificate (issuer, workflow identity) and verify it
against the Sigstore log, use gitsign:

```sh
gitsign verify-tags <version> \
  --certificate-identity-regexp 'https://github.com/MahdiBaghbani/opencloudmesh-go/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A successful verification ties the tag to a GitHub Actions run of
`release.yml` on this repository, authenticated by GitHub Actions OIDC. No
long-lived GPG key is involved.
