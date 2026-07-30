# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

# Verify workflow action refs match .github/action-pins.yml (immutable SHA pins).

use ./action-pins-common.nu [load-action-pins-context]

const HEX40 = '^[a-f0-9]{40}$'
const USES_LINE = 'uses:\s*(?<action>[^@\s]+)@(?<ref>\S+)'

def is-hex40-lowercase [s: string] {
  ($s | str length) == 40 and ($s =~ $HEX40)
}

def scan-workflow-uses [text: string] {
  mut found = []
  for line in ($text | lines) {
    let parsed = ($line | parse -r $USES_LINE)
    if not ($parsed | is-empty) {
      $found = ($found | append {
        action: ($parsed.action.0)
        ref: ($parsed.ref.0)
      })
    }
  }
  $found
}

def main [] {
  let ctx = (load-action-pins-context)
  let manifest = $ctx.manifest

  mut errors = []
  mut expected = {}

  for item in ($manifest.pins | default {} | items {|action, entry| { action: $action, entry: $entry }}) {
    let raw_sha = ($item.entry.sha? | default null)
    if ($raw_sha | describe) != 'string' {
      $errors = ($errors | append $"manifest: ($item.action) sha must be a string")
      continue
    }
    if $raw_sha != ($raw_sha | str downcase) {
      $errors = ($errors | append $"manifest: ($item.action) sha must be lowercase")
    }
    if not (is-hex40-lowercase $raw_sha) {
      $errors = ($errors | append $"manifest: ($item.action) sha must be exactly 40 lowercase hex chars")
      continue
    }
    $expected = ($expected | upsert $item.action $raw_sha)
  }

  for path in $ctx.workflow_paths {
    let text = (open --raw $path)
    for use in (scan-workflow-uses $text) {
      if not (is-hex40-lowercase $use.ref) {
        $errors = ($errors | append $"($path): mutable or malformed pin ($use.action)@($use.ref)")
        continue
      }
      if $use.action not-in ($expected | columns) {
        $errors = ($errors | append $"($path): unlisted action ($use.action)")
        continue
      }
      if ($expected | get $use.action) != $use.ref {
        $errors = ($errors | append $"($path): ($use.action)@($use.ref) != manifest ($expected | get $use.action)")
      }
    }
  }

  if not ($errors | is-empty) {
    $errors | each {|e| print --stderr $e }
    exit 1
  }

  print 'action-pins: OK'
}
