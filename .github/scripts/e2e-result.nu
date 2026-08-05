# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# Gate the e2e workflow on job results. Reads CHANGES and RESULT; exits 0
# only when CHANGES=success and RESULT is success or skipped.

def main [] {
  let changes = ($env.CHANGES? | default '')
  let result = ($env.RESULT? | default '')

  print $"changes result: ($changes)"
  print $"e2e result: ($result)"

  if $changes != 'success' {
    exit 1
  }
  if $result == 'success' or $result == 'skipped' {
    exit 0
  } else {
    exit 1
  }
}
