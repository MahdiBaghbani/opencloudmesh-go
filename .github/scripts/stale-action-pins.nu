# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Report-only action pin update check. Flags pins when a newer upstream
# release is available (resolved via `gh api`; GH_TOKEN auth is picked up by
# gh itself). Age is not a criterion: a pin that is the latest release is
# current even if old. Never blocks CI: output goes to the job log
# (::warning) and the step summary only, and the script always exits 0.

use ./action-pins-common.nu [load-action-pins-context]

# gh --jq prints the literal string "null" for missing fields; treat it as empty.
def clean-date [raw: string] {
  let date = ($raw | str trim)
  if ($date | is-empty) or $date == 'null' {
    return null
  }
  $date
}

def gh-api-field [endpoint: string, jq: string] {
  let res = (try {
    ^gh api $endpoint --jq $jq | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'gh not found'}
  })
  if $res.exit_code != 0 {
    return null
  }
  clean-date $res.stdout
}

def gh-api-lines [endpoint: string, jq: string] {
  let res = (try {
    ^gh api $endpoint --jq $jq | complete
  } catch {
    {exit_code: 127, stdout: '', stderr: 'gh not found'}
  })
  if $res.exit_code != 0 {
    return []
  }
  $res.stdout
  | lines
  | each {|line| $line | str trim}
  | where {|line| not ($line | is-empty) and $line != 'null'}
}

# Monorepo actions are owner/repo/subpath; GitHub API only knows owner/repo.
def action-owner-repo [action: string] {
  $action | split row '/' | first 2 | str join '/'
}

# Strip one leading v/V; require major.minor.patch with optional prerelease.
def semver-parse [tag: string] {
  mut t = ($tag | str trim)
  if ($t | str starts-with 'v') or ($t | str starts-with 'V') {
    $t = ($t | str substring 1..)
  }
  let parsed = (try {
    $t | parse --regex '^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<pre>.+))?$'
  } catch {
    []
  })
  if ($parsed | is-empty) {
    return null
  }
  let row = ($parsed | first)
  let pre_raw = ($row.pre? | default '')
  {
    major: ($row.major | into int)
    minor: ($row.minor | into int)
    patch: ($row.patch | into int)
    pre: (if ($pre_raw | is-empty) { null } else { $pre_raw })
  }
}

# -1 if a < b, 0 if equal, 1 if a > b; null if either tag is not semver.
def semver-compare [a: string, b: string] {
  let pa = (semver-parse $a)
  let pb = (semver-parse $b)
  if $pa == null or $pb == null {
    return null
  }
  if $pa.major < $pb.major { return (-1) }
  if $pa.major > $pb.major { return 1 }
  if $pa.minor < $pb.minor { return (-1) }
  if $pa.minor > $pb.minor { return 1 }
  if $pa.patch < $pb.patch { return (-1) }
  if $pa.patch > $pb.patch { return 1 }
  if $pa.pre == null and $pb.pre == null { return 0 }
  if $pa.pre == null { return 1 }
  if $pb.pre == null { return (-1) }
  if $pa.pre < $pb.pre { return (-1) }
  if $pa.pre > $pb.pre { return 1 }
  0
}

# Primary: stable-semver releases/latest. Fallback: max stable semver from
# releases + tags (skips non-semver "latest" tags such as codeql-bundle-*).
def resolve-latest-release [owner_repo: string] {
  let latest = (gh-api-field $"repos/($owner_repo)/releases/latest" '.tag_name')
  if $latest != null {
    let parsed = (semver-parse $latest)
    if $parsed != null and $parsed.pre == null {
      return $latest
    }
  }
  let release_tags = (gh-api-lines $"repos/($owner_repo)/releases?per_page=100" '.[].tag_name')
  let name_tags = (gh-api-lines $"repos/($owner_repo)/tags?per_page=100" '.[].name')
  let stable = (
    ($release_tags | append $name_tags | uniq)
    | each {|tag|
      let parsed = (semver-parse $tag)
      if $parsed == null or $parsed.pre != null {
        null
      } else {
        $tag
      }
    }
    | where {|tag| $tag != null}
  )
  if ($stable | is-empty) {
    return null
  }
  $stable
  | reduce {|tag, acc|
    let cmp = (semver-compare $tag $acc)
    if $cmp != null and $cmp > 0 { $tag } else { $acc }
  }
}

def append-summary [path: any, lines: list<string>] {
  if $path == null {
    return
  }
  try {
    (($lines | str join "\n") + "\n") | save --append $path
  } catch {|err|
    print --stderr $"stale-action-pins: could not write step summary: ($err.msg)"
  }
}

def main [] {
  let summary_path = ($env.GITHUB_STEP_SUMMARY? | default null)
  let heading = '## Action pin update check'

  let ctx = (try { load-action-pins-context } catch { null })
  if $ctx == null {
    print '::warning ::stale-action-pins: could not load the action pins manifest; check skipped'
    append-summary $summary_path [$heading '' '- WARNING: could not load the action pins manifest; check skipped']
    return
  }

  let pins = ($ctx.manifest.pins? | default {} | items {|action, entry|
    {
      action: $action
      release: ($entry.release? | default '')
      sha: ($entry.sha? | default '')
    }
  } | sort-by action)

  mut updates = []
  mut unresolved = []

  for pin in $pins {
    let owner_repo = (action-owner-repo $pin.action)
    let latest = (resolve-latest-release $owner_repo)
    if $latest == null {
      $unresolved = ($unresolved | append ($pin | insert reason 'no-upstream'))
      print $"::warning ::stale-action-pins: no upstream release/tag found for ($pin.action) release=($pin.release) sha=($pin.sha)"
      continue
    }
    let cmp = (semver-compare $latest $pin.release)
    if $cmp == null {
      $unresolved = ($unresolved | append ($pin | insert latest $latest | insert reason 'unparseable'))
      print $"::warning ::stale-action-pins: cannot compare release tags for ($pin.action): pinned ($pin.release), latest ($latest)"
      continue
    }
    if $cmp > 0 {
      $updates = ($updates | append ($pin | insert latest $latest))
      print $"::warning ::update available for ($pin.action): pinned ($pin.release), latest ($latest)"
    }
  }

  let counts = $"($pins | length) pins checked, ($updates | length) updates available, ($unresolved | length) unresolved"
  print $"stale-action-pins: ($counts)"

  mut lines = [$heading '' $counts '']
  $lines = ($lines | append ($updates | each {|item|
    $"- UPDATE: ($item.action) pinned ($item.release) -> latest ($item.latest)"
  }))
  $lines = ($lines | append ($unresolved | each {|pin|
    if ($pin.reason? | default '') == 'unparseable' {
      $"- UNRESOLVED: ($pin.action) pinned ($pin.release), latest ($pin.latest)"
    } else {
      $"- UNRESOLVED: ($pin.action) release=($pin.release) sha=($pin.sha) \(no upstream release/tag\)"
    }
  }))

  append-summary $summary_path $lines
}
