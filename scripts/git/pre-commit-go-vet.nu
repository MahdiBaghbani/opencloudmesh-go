# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Vet the full module from index snapshot (not dirty worktree). Skipped when no staged Go files.

def main [...files: string] {
  if ($files | is-empty) {
    return
  }

  if (which git | is-empty) {
    print "git not found"
    exit 1
  }
  if (which go | is-empty) {
    print "go not found"
    exit 1
  }

  let tmp_result = (^mktemp -d | complete)
  if $tmp_result.exit_code != 0 {
    print "pre-commit: failed to create temp dir"
    exit 1
  }
  let tmp = ($tmp_result.stdout | str trim | path expand)

  mut failed = false
  try {
    let checkout = (^git checkout-index --prefix=$"($tmp)/" -a | complete)
    if $checkout.exit_code != 0 {
      print "pre-commit: checkout-index failed"
      let err = ($checkout.stderr | str trim)
      if ($err | is-not-empty) {
        print $err
      }
      $failed = true
    } else {
      let vet = (do { cd $tmp; ^go vet ./... } | complete)
      if $vet.exit_code != 0 {
        print "pre-commit: go vet failed"
        let err = ($vet.stderr | str trim)
        if ($err | is-not-empty) {
          print $err
        }
        let out = ($vet.stdout | str trim)
        if ($out | is-not-empty) {
          print $out
        }
        $failed = true
      }
    }
  } finally {
    let cleanup = (^rm -rf $tmp | complete)
    if $cleanup.exit_code != 0 {
      print "pre-commit: failed to remove temp dir"
      let err = ($cleanup.stderr | str trim)
      if ($err | is-not-empty) {
        print $err
      }
      exit 1
    }
  }

  if $failed {
    exit 1
  }
}
