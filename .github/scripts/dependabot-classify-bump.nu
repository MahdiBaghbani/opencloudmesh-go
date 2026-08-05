# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Classify a Dependabot bump as patch/minor/major and decide automerge.
# Reads UPDATE_TYPE, PREV, NEW; appends level and automerge to GITHUB_OUTPUT.

def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

# Strip one leading lowercase v, matching bash ${VAR#v}.
def strip-leading-v [version: string] {
  if ($version | str starts-with 'v') {
    $version | str substring 1..
  } else {
    $version
  }
}

# Segment before the first dot (bash ${VAR%%.*}).
def before-first-dot [version: string] {
  let parts = ($version | split row '.')
  $parts | first
}

# Segment after the first dot (bash ${VAR#*.}); empty if no dot.
def after-first-dot [version: string] {
  let idx = ($version | str index-of '.')
  if $idx == null {
    ''
  } else {
    $version | str substring ($idx + 1)..
  }
}

def main [] {
  let update_type = ($env.UPDATE_TYPE? | default '')
  let prev_raw = ($env.PREV? | default '')
  let new_raw = ($env.NEW? | default '')

  mut level = ''
  match $update_type {
    'version-update:semver-patch' => { $level = 'patch' }
    'version-update:semver-minor' => { $level = 'minor' }
    'version-update:semver-major' => { $level = 'major' }
    _ => {}
  }

  if ($level | is-empty) and (not ($prev_raw | is-empty)) and (not ($new_raw | is-empty)) {
    let prev = (strip-leading-v $prev_raw)
    let new = (strip-leading-v $new_raw)
    if (before-first-dot $new) != (before-first-dot $prev) {
      $level = 'major'
    } else {
      let prev_mm = (after-first-dot $prev)
      let new_mm = (after-first-dot $new)
      if (before-first-dot $new_mm) != (before-first-dot $prev_mm) {
        $level = 'minor'
      } else {
        $level = 'patch'
      }
    }
  }

  append-output 'level' $level
  if $level == 'patch' or $level == 'minor' {
    append-output 'automerge' 'true'
  } else {
    append-output 'automerge' 'false'
  }
}
