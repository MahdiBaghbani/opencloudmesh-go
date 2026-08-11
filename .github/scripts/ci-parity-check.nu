# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Assert rollup needs keys, *_RESULT env vars, and ci-require-jobs.nu names match.

def get-needs-names [] {
  let needs_json = ($env | get --optional NEEDS_JSON | default '')
  if ($needs_json | is-empty) {
    print --stderr 'ci-parity-check: NEEDS_JSON env required'
    exit 1
  }
  $needs_json | from json | columns | each {|k| $k | str lowercase} | sort
}

def get-env-names [] {
  $env
  | transpose k v
  | get k
  | where {|k| ($k | str ends-with '_RESULT')}
  | each {|k| $k | str replace -a '_RESULT' '' | str lowercase}
  | sort
}

def get-script-names [] {
  let parsed = (
    open .github/scripts/ci-require-jobs.nu
    | parse --regex "require-success '([A-Z0-9_]+_RESULT)'"
  )
  let capture_col = if ('capture1' in ($parsed | columns)) { 'capture1' } else { 'capture0' }
  $parsed
  | get $capture_col
  | each {|name| $name | str replace -a '_RESULT' '' | str lowercase}
  | sort
  | uniq
}

def main [] {
  let needs = (get-needs-names)
  let env_names = (get-env-names)
  let script_names = (get-script-names)

  if ($needs == $env_names) and ($needs == $script_names) {
    print 'ci-parity-check: OK'
    return
  }

  print --stderr 'ci-parity-check: name-set mismatch'
  print --stderr $"  needs:   ($needs | to json -r)"
  print --stderr $"  env:     ($env_names | to json -r)"
  print --stderr $"  script:  ($script_names | to json -r)"

  let only_in_needs = ($needs | where {|n| $n not-in $env_names and $n not-in $script_names})
  let only_in_env = ($env_names | where {|n| $n not-in $needs and $n not-in $script_names})
  let only_in_script = ($script_names | where {|n| $n not-in $needs and $n not-in $env_names})

  if not ($only_in_needs | is-empty) {
    print --stderr $"  only in needs:   ($only_in_needs | to json -r)"
  }
  if not ($only_in_env | is-empty) {
    print --stderr $"  only in env:     ($only_in_env | to json -r)"
  }
  if not ($only_in_script | is-empty) {
    print --stderr $"  only in script:  ($only_in_script | to json -r)"
  }

  exit 1
}
