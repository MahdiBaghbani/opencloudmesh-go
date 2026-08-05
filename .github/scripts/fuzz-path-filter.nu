# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Path filter for fuzz CI: set run=true when the BASE_SHA...HEAD diff
# touches fuzz-relevant paths. Reads BASE_SHA; appends run to GITHUB_OUTPUT.

const FUZZ_PATH_RE = '^(internal/platform/crypto/|internal/components/ocm/spec/|go\.mod$|go\.sum$|Makefile$|\.github/workflows/ci-test-fuzz\.yml$)'

def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

def main [] {
  let base_sha = ($env.BASE_SHA? | default '')
  let res = (try {
    ^git diff --name-only $"($base_sha)...HEAD" | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'git not found'}
  })
  if $res.exit_code != 0 {
    let stderr_msg = (try { $res.stderr } catch { 'Unknown error' })
    print --stderr $"fuzz-path-filter: git diff failed: ($stderr_msg)"
    exit $res.exit_code
  }

  let changed = ($res.stdout | lines | where {|line| not ($line | is-empty)})
  let matched = ($changed | any {|path| $path =~ $FUZZ_PATH_RE})

  if $matched {
    append-output 'run' 'true'
  } else {
    append-output 'run' 'false'
    print 'No fuzz-relevant changes; skipping.'
  }
}
