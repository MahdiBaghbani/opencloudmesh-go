# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Apply e2e change gate: schedule/workflow_dispatch force e2e=true, else e2e=$FILTERED.
# Reads EVENT, FILTERED; appends e2e to GITHUB_OUTPUT.

def append-output [name: string, value: string] {
  $"($name)=($value)\n" | save --append $env.GITHUB_OUTPUT
}

def main [] {
  let event = ($env.EVENT? | default '')
  let filtered = ($env.FILTERED? | default '')
  let force = ($event == 'schedule') or ($event == 'workflow_dispatch')

  if $force {
    append-output 'e2e' 'true'
  } else {
    append-output 'e2e' $filtered
  }
}
