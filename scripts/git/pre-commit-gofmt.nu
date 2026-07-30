# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

# Fail when staged Go files need gofmt. Validates index blobs, not worktree.

def main [...files: string] {
  if ($files | is-empty) {
    return
  }

  if (which gofmt | is-empty) {
    print "gofmt not found"
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
      do { ^git show $":($path)" | ^gofmt -l } | complete
    } catch {
      {exit_code: 127, stdout: "", stderr: "gofmt not found"}
    })
    if $check.exit_code != 0 {
      print "pre-commit: gofmt failed"
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
    print "pre-commit: gofmt needed on:"
    for f in $needs_fmt {
      print $"  ($f)"
    }
    print "Run: make fmt"
    exit 1
  }
}
