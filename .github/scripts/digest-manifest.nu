# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Write a docker digest manifest JSON and publish its path as a step output.
# Reads SEMVER_TAG, FULL_SHA, IMAGE_DIGEST, IMAGE; appends manifest_path.

def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

def main [] {
  let semver_tag = ($env.SEMVER_TAG? | default '')
  let full_sha = ($env.FULL_SHA? | default '')
  let image_digest = ($env.IMAGE_DIGEST? | default '')
  let image = ($env.IMAGE? | default '')

  if ($image_digest | is-empty) {
    print 'Missing image digest from build-push step'
    exit 1
  }

  let manifest = $"digest-manifest-($semver_tag)-($full_sha).json"
  let body = ({
    image: $image
    semver_tag: $semver_tag
    commit_sha: $full_sha
    sha_tag: $"sha-($full_sha)"
    digest: $image_digest
  } | to json | str trim)

  ($body + "\n") | save --force $manifest
  print $body
  append-output 'manifest_path' $manifest
}
