# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Resolve and validate the docker image semver tag for build-push-docker.
# Reads DISPATCH_SEMVER, GITHUB_EVENT_NAME, GITHUB_REF_TYPE, GITHUB_REF.
# Appends semver_tag, full_sha, sha_tag to GITHUB_OUTPUT.

use ./release-semver-common.nu [semver-ok, append-output, git-head-sha]

def main [] {
  let event_name = ($env.GITHUB_EVENT_NAME? | default '')
  let ref_type = ($env.GITHUB_REF_TYPE? | default '')
  let github_ref = ($env.GITHUB_REF? | default '')
  let dispatch_semver = ($env.DISPATCH_SEMVER? | default '')

  mut semver_tag = ''
  if $event_name == 'workflow_dispatch' or $event_name == 'workflow_call' {
    if ($dispatch_semver | is-empty) {
      print 'workflow_dispatch/workflow_call requires inputs.semver'
      exit 1
    }
    $semver_tag = $dispatch_semver
  } else if $ref_type == 'tag' {
    if ($github_ref | str starts-with 'refs/tags/') {
      $semver_tag = ($github_ref | str substring 10..)
    } else {
      $semver_tag = $github_ref
    }
  } else {
    print $"Ref ($github_ref) does not carry a semver tag"
    exit 1
  }

  if not (semver-ok $semver_tag) {
    print $"Invalid semver tag: ($semver_tag)"
    exit 1
  }

  let full_sha = (git-head-sha --label resolve-semver-tag)

  append-output 'semver_tag' $semver_tag
  append-output 'full_sha' $full_sha
  append-output 'sha_tag' $"sha-($full_sha)"
  print $"SEMVER_TAG=($semver_tag)"
  print $"GITHUB_SHA=($full_sha)"
}
