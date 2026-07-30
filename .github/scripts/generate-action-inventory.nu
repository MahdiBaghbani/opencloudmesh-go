# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

# Print sorted action@sha inventory from workflow files.

use ./action-pins-common.nu [load-action-pins-context]

const USES_PIN = 'uses:\s*(?<action>[^@\s]+)@(?<sha>[a-f0-9]{40})\b'

def scan-workflow-pins [text: string] {
  mut found = []
  for line in ($text | lines) {
    let parsed = ($line | parse -r $USES_PIN)
    if not ($parsed | is-empty) {
      $found = ($found | append $"($parsed.action.0)@($parsed.sha.0)")
    }
  }
  $found
}

def main [] {
  let ctx = (load-action-pins-context)

  mut seen = []
  for path in $ctx.workflow_paths {
    let text = (open --raw $path)
    $seen = ($seen | append (scan-workflow-pins $text))
  }

  for line in ($seen | uniq | sort) {
    print $line
  }
}
