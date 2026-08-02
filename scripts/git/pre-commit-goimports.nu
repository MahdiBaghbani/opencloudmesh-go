# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Fail when staged Go files need goimports. Validates index blobs, not worktree.

def main [...files: string] {
  if ($files | is-empty) {
    return
  }

  if (which goimports | is-empty) {
    print "goimports not found; install with: make tools"
    exit 1
  }

  mut needs_fmt = []
  for path in $files {
    let probe = (^git cat-file -e $":($path)" | complete)
    if $probe.exit_code != 0 {
      continue
    }

    let blob = (try {
      ^git cat-file blob $":($path)" | into binary
    } catch {
      null
    })
    if $blob == null {
      continue
    }
    if ($blob | bytes index-of 0x[00]) >= 0 {
      continue
    }

    let check = (try {
      do { ^git show $":($path)" | ^goimports -l -srcdir $path } | complete
    } catch {
      {exit_code: 127, stdout: "", stderr: "goimports not found"}
    })
    if $check.exit_code != 0 {
      print "pre-commit: goimports failed"
      let err = ($check.stderr | str trim)
      if ($err | is-not-empty) {
        print $err
      }
      exit 1
    }
    if ($check.stdout | str trim | is-not-empty) {
      $needs_fmt = ($needs_fmt | append $path)
    }
  }

  if not ($needs_fmt | is-empty) {
    print "pre-commit: goimports needed on:"
    for f in $needs_fmt {
      print $"  ($f)"
    }
    print "Run: make fmt"
    print "Install goimports with: make tools"
    exit 1
  }
}
