# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Shared semver validation and git helpers for release workflows.

# Core: no leading zeros. Prerelease ids: 0 | [1-9][0-9]* | alnum/hyphen with a letter/hyphen.
# Build metadata (+...) rejected. Same check for workflow_dispatch, workflow_call, and tag push.
# Plain single-quoted string: interpolated $"..." treats [0-9] as an unclosed delimiter.
export const SEMVER_RE = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'

export def semver-ok [tag: string] {
  $tag =~ $SEMVER_RE
}

export def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

export def git-head-sha [
  --label (-l): string = 'release-semver-common'
] {
  let rev = (try {
    ^git rev-parse HEAD | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'git not found'}
  })
  if $rev.exit_code != 0 {
    let stderr_msg = (try { $rev.stderr } catch { 'Unknown error' })
    print --stderr $"($label): git rev-parse failed: ($stderr_msg)"
    exit $rev.exit_code
  }
  $rev.stdout | str trim
}

export def peel-tag-commit [
  tag: string
  --label (-l): string = 'release-semver-common'
] {
  let tag_ref = $"refs/tags/($tag)"
  let type_rev = (try {
    ^git cat-file -t $tag_ref | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'git not found'}
  })
  if $type_rev.exit_code != 0 {
    let stderr_msg = (try { $type_rev.stderr } catch { 'Unknown error' })
    print --stderr $"($label): tag ($tag) not found: ($stderr_msg)"
    exit $type_rev.exit_code
  }
  let objtype = ($type_rev.stdout | str trim)
  if $objtype != 'tag' {
    print --stderr ($label + ': ' + $tag + ' is not an annotated tag (got ' + $objtype + ')')
    exit 1
  }
  let rev = (try {
    ^git rev-parse --verify $"($tag_ref)^{commit}" | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'git not found'}
  })
  if $rev.exit_code != 0 {
    let stderr_msg = (try { $rev.stderr } catch { 'Unknown error' })
    print --stderr $"($label): git rev-parse --verify ($tag_ref)^{commit} failed: ($stderr_msg)"
    exit $rev.exit_code
  }
  $rev.stdout | str trim
}
