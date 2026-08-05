# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Shared context loader for action-pin helpers.

export const INSTALL_NUSHELL_ARCHIVE_KEY = 'nushell/nushell'
export const INSTALL_NUSHELL_ACTION_REL = '.github/actions/install-nushell/action.yml'

const HEX64 = '^[a-f0-9]{64}$'
const NU_SHA256_ENV = 'NU_SHA256:\s*(?<raw>[^\s#]+)'
const NU_ASSET_URL_FRAGMENT = 'nu-${NU_VERSION}-x86_64-unknown-linux-gnu.tar.gz'
const SHA256SUM_CHECK = 'sha256sum\s+-c'

def is-hex64-lowercase [s: string] {
  ($s | str length) == 64 and ($s =~ $HEX64)
}

def strip-yaml-quotes [s: string] {
  let t = ($s | str trim)
  if ($t | str starts-with "'") and ($t | str ends-with "'") {
    return ($t | str substring 1..-2)
  }
  if ($t | str starts-with '"') and ($t | str ends-with '"') {
    return ($t | str substring 1..-2)
  }
  $t
}

def is-record-value [x: any] {
  (($x | describe) | str starts-with 'record')
}

def expected-nushell-asset [version: string] {
  $"nu-($version)-x86_64-unknown-linux-gnu.tar.gz"
}

export def install-nushell-action-path [root: string] {
  $root | path join $INSTALL_NUSHELL_ACTION_REL
}

# Validate manifest.archives entries. When install-nushell exists, the
# nushell/nushell entry is required. Returns parsed nushell entry or null.
export def validate-archives-manifest [manifest: record, root: string] {
  mut errors = []
  let install_action = (install-nushell-action-path $root)
  let needs_nushell_archive = ($install_action | path exists)
  let archives = ($manifest.archives? | default null)

  if $needs_nushell_archive and (
    ($archives | describe) == 'nothing' or $archives == null
  ) {
    return {
      errors: [
        'manifest: missing archives section (required for install-nushell digest pinning)'
      ]
      nushell_entry: null
    }
  }

  if ($archives | describe) == 'nothing' or $archives == null {
    return { errors: [], nushell_entry: null }
  }

  if not (is-record-value $archives) {
    return {
      errors: ['manifest: archives must be a mapping']
      nushell_entry: null
    }
  }

  if $needs_nushell_archive and $INSTALL_NUSHELL_ARCHIVE_KEY not-in ($archives | columns) {
    $errors = ($errors | append $"manifest: archives missing ($INSTALL_NUSHELL_ARCHIVE_KEY) entry")
  }

  mut nushell_entries = []

  for item in ($archives | items {|key, entry| { key: $key, entry: $entry }}) {
    let prefix = $"manifest: archives.($item.key)"

    if not (is-record-value $item.entry) {
      $errors = ($errors | append $"($prefix) must be a mapping")
      continue
    }

    let version = ($item.entry.version? | default null)
    if ($version | describe) != 'string' or ($version | str trim | is-empty) {
      $errors = ($errors | append $"($prefix) version must be a non-empty string")
      continue
    }

    let asset = ($item.entry.asset? | default null)
    if ($asset | describe) != 'string' or ($asset | str trim | is-empty) {
      $errors = ($errors | append $"($prefix) asset must be a non-empty string")
      continue
    }

    let raw_sha = ($item.entry.sha256? | default null)
    if ($raw_sha | describe) != 'string' {
      $errors = ($errors | append $"($prefix) sha256 must be a string")
      continue
    }
    if $raw_sha != ($raw_sha | str downcase) {
      $errors = ($errors | append $"($prefix) sha256 must be lowercase")
    }
    if not (is-hex64-lowercase $raw_sha) {
      $errors = ($errors | append $"($prefix) sha256 must be exactly 64 lowercase hex chars")
      continue
    }

    if $item.key == $INSTALL_NUSHELL_ARCHIVE_KEY {
      let expected_asset = (expected-nushell-asset $version)
      if $asset != $expected_asset {
        $errors = ($errors | append $"($prefix) asset ($asset) != expected ($expected_asset)")
      }
      $nushell_entries = (
        $nushell_entries
        | append {
          version: $version
          asset: $asset
          sha256: $raw_sha
        }
      )
    }
  }

  let nushell_entry = (
    if ($nushell_entries | is-empty) {
      null
    } else {
      ($nushell_entries | first)
    }
  )

  { errors: $errors, nushell_entry: $nushell_entry }
}

# Parse digest-pin fields from the install-nushell composite action. The
# composite lane should expose NU_SHA256 in env and verify with sha256sum -c.
export def parse-install-nushell-composite [text: string] {
  mut sha256: any = null
  for line in ($text | lines) {
    let parsed = ($line | parse -r $NU_SHA256_ENV)
    if not ($parsed | is-empty) {
      $sha256 = (strip-yaml-quotes ($parsed.raw.0))
    }
  }
  {
    sha256: $sha256
    has_asset_pattern: ($text | str contains $NU_ASSET_URL_FRAGMENT)
    has_sha256_check: ($text =~ $SHA256SUM_CHECK)
  }
}

export def validate-install-nushell-composite-drift [
  entry: record,
  composite: record,
  action_path: string
] {
  mut errors = []

  if $composite.sha256 == null {
    $errors = ($errors | append $"($action_path): missing NU_SHA256 env pin; expected manifest archives.($INSTALL_NUSHELL_ARCHIVE_KEY).sha256")
  } else {
    if not (is-hex64-lowercase $composite.sha256) {
      $errors = ($errors | append $"($action_path): NU_SHA256 must be exactly 64 lowercase hex chars")
    } else if $composite.sha256 != $entry.sha256 {
      $errors = ($errors | append $"($action_path): NU_SHA256 ($composite.sha256) != manifest ($entry.sha256)")
    }
  }

  if not $composite.has_asset_pattern {
    $errors = ($errors | append $"($action_path): download URL must reference ($NU_ASSET_URL_FRAGMENT)")
  }

  if not $composite.has_sha256_check {
    $errors = ($errors | append $"($action_path): missing sha256sum -c digest verification before extraction")
  }

  $errors
}

def find-repo-root [] {
  let script_pwd = ($env.FILE_PWD? | default null)
  if $script_pwd != null {
    let from_script = ($script_pwd | path dirname | path dirname)
    if ($from_script | path join '.github' 'action-pins.yml' | path exists) {
      return $from_script
    }
  }
  let cwd = (pwd | path expand)
  if ($cwd | path join '.github' 'action-pins.yml' | path exists) {
    return $cwd
  }
  error make { msg: 'Could not find repo root (missing .github/action-pins.yml)' }
}

def list-workflow-paths [workflows_dir: string] {
  let yml = (glob ($workflows_dir | path join '*.yml'))
  let yaml = (glob ($workflows_dir | path join '*.yaml'))
  $yml | append $yaml | uniq | sort
}

def list-action-paths [root: string] {
  let yml = (glob ($root | path join '**' 'action.yml'))
  let yaml = (glob ($root | path join '**' 'action.yaml'))
  $yml | append $yaml | uniq | sort
}

# Load repo root, action-pins manifest, and sorted paths to scan for uses:
# pins: workflow files (*.yml + *.yaml) plus composite action manifests
# (**/action.yml + **/action.yaml). Fails non-zero when no workflow files match.
export def load-action-pins-context [] {
  let root = (find-repo-root)
  let manifest_path = ($root | path join '.github' 'action-pins.yml')
  let workflows_dir = ($root | path join '.github' 'workflows')
  let manifest = (open $manifest_path)
  let workflow_paths = (list-workflow-paths $workflows_dir)
  if ($workflow_paths | is-empty) {
    error make {
      msg: 'No workflow files found under .github/workflows (*.yml, *.yaml)'
    }
  }
  # Fold composite-action manifests into the scan set so existing consumers
  # (verify / inventory) cover uses: pins inside action.yml / action.yaml too.
  let scan_paths = (
    $workflow_paths
    | append (list-action-paths $root)
    | uniq
    | sort
  )
  {
    root: $root
    manifest_path: $manifest_path
    manifest: $manifest
    workflows_dir: $workflows_dir
    workflow_paths: $scan_paths
  }
}
