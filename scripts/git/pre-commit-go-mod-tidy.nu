# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Fail when staged go.mod/go.sum need go mod tidy. Validates index snapshot, not worktree.

def read-index-blob [path: string] {
  let probe = (^git cat-file -e $":($path)" | complete)
  if $probe.exit_code != 0 {
    return { ok: false, missing: true, content: "" }
  }

  let read = (^git show $":($path)" | complete)
  if $read.exit_code != 0 {
    return { ok: false, missing: false, content: "" }
  }
  { ok: true, missing: false, content: $read.stdout }
}

def read-file-text [path: string] {
  if not ($path | path exists) {
    return { ok: false, content: "" }
  }
  try {
    { ok: true, content: (open $path -r) }
  } catch {
    { ok: false, content: "" }
  }
}

def main [] {
  if (which git | is-empty) {
    print "git not found"
    exit 1
  }
  if (which go | is-empty) {
    print "go not found"
    exit 1
  }

  let staged_mod = (read-index-blob "go.mod")
  if $staged_mod.missing {
    print "pre-commit: go.mod not in index"
    exit 1
  }
  if not $staged_mod.ok {
    print "pre-commit: failed to read staged go.mod"
    exit 1
  }

  let staged_sum = (read-index-blob "go.sum")
  if not $staged_sum.missing and not $staged_sum.ok {
    print "pre-commit: failed to read staged go.sum"
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
      let tidy = (do { cd $tmp; ^go mod tidy } | complete)
      if $tidy.exit_code != 0 {
        print "pre-commit: go mod tidy failed"
        let err = ($tidy.stderr | str trim)
        if ($err | is-not-empty) {
          print $err
        }
        $failed = true
      } else {
        let tidied_mod = (read-file-text $"($tmp)/go.mod")
        if not $tidied_mod.ok {
          print "pre-commit: go mod tidy did not produce go.mod"
          $failed = true
        } else if $tidied_mod.content != $staged_mod.content {
          print "pre-commit: go.mod differs from go mod tidy output"
          print "Run: go mod tidy"
          $failed = true
        }

        if not $failed {
          let tidied_sum = (read-file-text $"($tmp)/go.sum")
          if $staged_sum.missing {
            if $tidied_sum.ok {
              print "pre-commit: go.sum missing from index but required after go mod tidy"
              print "Run: go mod tidy"
              $failed = true
            }
          } else if not $tidied_sum.ok {
            print "pre-commit: go.sum in index but absent after go mod tidy"
            print "Run: go mod tidy"
            $failed = true
          } else if $tidied_sum.content != $staged_sum.content {
            print "pre-commit: go.sum differs from go mod tidy output"
            print "Run: go mod tidy"
            $failed = true
          }
        }
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
