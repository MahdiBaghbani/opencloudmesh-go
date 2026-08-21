# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Smoke tests for changelog-skip-check.nu via env-driven main invocations.

def read-skip [output_path: path] {
  open $output_path
  | lines
  | where $it =~ '^skip='
  | first
  | str replace 'skip=' ''
}

def run-case [
  name: string,
  event: record,
  extra_env: record,
  expect_skip: string,
] {
  let mktemp_r = (^mktemp -d "/tmp/changelog-skip-check-test.XXXXXX" | complete)
  if $mktemp_r.exit_code != 0 {
    print $"FAIL ($name): mktemp failed"
    exit 1
  }
  let dir = ($mktemp_r.stdout | str trim)
  let event_path = ($dir | path join 'event.json')
  let output_path = ($dir | path join 'output.txt')
  $event | to json | save $event_path

  let script = ($env.PWD | path join '.github/scripts/changelog-skip-check.nu')
  let env_vars = (
    {
      GITHUB_EVENT_PATH: $event_path
      GITHUB_OUTPUT: $output_path
      PR_AUTHOR: ''
    }
    | merge $extra_env
  )

  let _run = (with-env $env_vars { nu $script })
  let skip = (read-skip $output_path)
  if $skip != $expect_skip {
    print $"FAIL ($name): expected skip=($expect_skip), got skip=($skip)"
    exit 1
  }
  print $"OK ($name): skip=($skip)"
}

def main [] {
  let base_event = {
    pull_request: {
      head: { ref: 'feature/foo' }
      title: 'feat: something'
      labels: []
    }
  }

  run-case 'dependabot' $base_event { PR_AUTHOR: 'dependabot[bot]' } 'true'
  run-case 'release title' {
    pull_request: {
      head: { ref: 'feature/foo' }
      title: 'chore(release): 1.2.3'
      labels: []
    }
  } {} 'true'
  run-case 'skip-changelog label' {
    pull_request: {
      head: { ref: 'feature/foo' }
      title: 'feat: something'
      labels: [{ name: 'skip-changelog' }]
    }
  } {} 'true'
  run-case 'product unchanged' $base_event { PRODUCT_CHANGED: 'false' } 'true'
  run-case 'product changed' $base_event { PRODUCT_CHANGED: 'true' } 'false'
  run-case 'product filter unset' $base_event {} 'false'

  print 'All changelog-skip-check tests passed.'
}
