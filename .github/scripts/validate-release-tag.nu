# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Validate an existing release tag: semver shape, tag exists, changelog file.

use ./release-semver-common.nu [semver-ok, peel-tag-commit]

def main [
  --tag (-t): string = ''
] {
  let tag = if ($tag | is-empty) { $env.TAG? | default '' } else { $tag }
  if ($tag | is-empty) {
    print --stderr 'validate-release-tag: --tag or TAG env required'
    exit 1
  }

  if not (semver-ok $tag) {
    print --stderr $"validate-release-tag: invalid semver tag: ($tag)"
    exit 1
  }

  peel-tag-commit $tag --label validate-release-tag

  let tag_ref = $"refs/tags/($tag)"
  let changelog = $".changes/($tag).md"
  let cat = (try {
    ^git cat-file -e $"($tag_ref):($changelog)" | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'git not found'}
  })
  if $cat.exit_code != 0 {
    print --stderr $"validate-release-tag: missing changelog in tag tree: ($tag_ref):($changelog)"
    exit 1
  }

  print $"validate-release-tag: ($tag) ok"
}
