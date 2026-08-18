# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Enforce a 500-line cap on tracked Go sources. Files over the limit need a
# valid // ocmgo:file-length-ignore directive in the header (before package).

const MAX_LINES = 500
const DIRECTIVE_MARKER = 'ocmgo:file-length-ignore'
const DIRECTIVE_RE = '^//\s*ocmgo:file-length-ignore:\s+(\S(?:.*\S)?)(?:\s+expires=(\d{4}-\d{2}-\d{2}))?(?:\s+owner=([A-Za-z0-9][A-Za-z0-9._-]*))?\s*$'

def tracked-go-files [] {
  let result = (^git ls-files '*.go' | complete)
  if $result.exit_code != 0 {
    print --stderr $"check-file-length: git ls-files failed: ($result.stderr)"
    exit 1
  }
  $result.stdout | lines | where {|f| not ($f | is-empty)}
}

def package-index [lines: list<string>] {
  $lines
  | enumerate
  | where {|e| ($e.item | str trim) =~ '^package\s'}
  | first
  | get index?
}

def parse-directive [line: string] {
  try {
    $line | parse --regex $DIRECTIVE_RE | first
  } catch {
    null
  }
}

def check-file [path: string, today: string] {
  let raw_lines = (open --raw $path | lines)
  let line_count = ($raw_lines | length)
  let pkg_idx = (package-index $raw_lines)

  let header = if $pkg_idx == null { $raw_lines } else { $raw_lines | take $pkg_idx }
  let after_pkg = if $pkg_idx == null { [] } else { $raw_lines | skip ($pkg_idx + 1) }

  let after_hits = ($after_pkg | where {|line| $line | str contains $DIRECTIVE_MARKER})
  if not ($after_hits | is-empty) {
    return {status: 'fail', message: $"($path): directive after package"}
  }

  let header_hits = ($header | where {|line| $line | str contains $DIRECTIVE_MARKER})
  if ($header_hits | length) > 1 {
    return {status: 'fail', message: $"($path): duplicate directive"}
  }

  if $line_count <= $MAX_LINES {
    return {status: 'pass', message: ''}
  }

  if ($header_hits | is-empty) {
    return {
      status: 'fail'
      message: $"($path): ($line_count) lines, exceeds ($MAX_LINES), and has no ocmgo:file-length-ignore directive"
    }
  }

  let directive_line = ($header_hits | first)
  let parsed = (parse-directive $directive_line)
  if $parsed == null {
    return {status: 'fail', message: $"($path): malformed directive"}
  }

  let reason = ($parsed.capture0? | default '')
  if ($reason | str trim | is-empty) {
    return {status: 'fail', message: $"($path): malformed directive - missing reason"}
  }
  if ($reason | str length) < 6 {
    return {status: 'fail', message: $"($path): reason too short (min 6 chars): ($reason)"}
  }

  let expires = ($parsed.capture1?)
  if ($expires != null) and ($today > $expires) {
    return {status: 'fail', message: $"($path): directive expired on ($expires)"}
  }

  {status: 'exempt', message: ''}
}

def main [] {
  let today = (date now | format date '%Y-%m-%d')
  let files = (tracked-go-files)
  mut violations = []
  mut exempt_count = 0

  for file in $files {
    let result = (check-file $file $today)
    if $result.status == 'fail' {
      $violations = ($violations | append $result.message)
    } else if $result.status == 'exempt' {
      $exempt_count = ($exempt_count + 1)
    }
  }

  if not ($violations | is-empty) {
    $violations | each {|msg| print --stderr $msg}
    exit 1
  }

  let file_count = ($files | length)
  print (["file-length: OK (" ($file_count | into string) " files checked, " ($exempt_count | into string) " over limit exempt)"] | str join "")
}
