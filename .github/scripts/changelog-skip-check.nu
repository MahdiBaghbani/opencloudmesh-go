# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Decide whether the changelog gate should skip. Reads PR_AUTHOR and
# GITHUB_EVENT_PATH; appends skip to GITHUB_OUTPUT. Always exits 0 on a
# successful decision; fails non-zero if the event file cannot be read.

def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

def main [] {
  let pr_author = ($env.PR_AUTHOR? | default '')
  if $pr_author == 'dependabot[bot]' {
    append-output 'skip' 'true'
    print 'Skipping changelog check: dependabot-authored PR'
    return
  }

  let event_path = ($env.GITHUB_EVENT_PATH? | default '')
  if ($event_path | is-empty) {
    print --stderr 'changelog-skip-check: GITHUB_EVENT_PATH is unset'
    exit 1
  }

  let event = (try {
    open --raw $event_path | from json
  } catch {|err|
    print --stderr $"changelog-skip-check: could not read event file: ($err.msg)"
    exit 1
  })

  # Reject non-records so malformed or non-object JSON surfaces as a hard fail.
  if ($event | describe) !~ '^record' {
    print --stderr 'changelog-skip-check: event file did not parse as a JSON object'
    exit 1
  }

  let labels = (
    $event.pull_request?.labels?
    | default []
    | each {|label| $label.name? | default ''}
    | where {|name| not ($name | is-empty)}
  )

  if ('skip-changelog' in $labels) {
    append-output 'skip' 'true'
    print 'Skipping changelog check: skip-changelog label'
    return
  }

  append-output 'skip' 'false'
  print 'No skip condition matched; running changelog gate.'
}
