# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Require every listed CI job result env var to be exactly "success".
# Workflow step must supply:
#   LINT_RESULT, SECURITY_RESULT, LICENSES_RESULT, TEST_RESULT,
#   BUILD_RESULT, ACTION_PINS_RESULT, REUSE_RESULT

def require-success [name: string] {
  let value = ($env | get --optional $name | default '')
  if $value != 'success' {
    print --stderr $"ci-require-jobs: ($name) must be success, got '($value)'"
    exit 1
  }
}

def main [] {
  require-success 'LINT_RESULT'
  # Security required: blocking gosec, govulncheck, and zizmor gates CI.
  require-success 'SECURITY_RESULT'
  # Licenses are blocking; unknown or out-of-allowlist licenses fail CI.
  require-success 'LICENSES_RESULT'
  require-success 'TEST_RESULT'
  require-success 'BUILD_RESULT'
  require-success 'ACTION_PINS_RESULT'
  require-success 'REUSE_RESULT'
}
