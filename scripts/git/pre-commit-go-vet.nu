# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

# Vet packages touched by staged Go files using index snapshot (not dirty worktree).

def main [...files: string] {
  if ($files | is-empty) {
    return
  }

  let pkgs = (
    $files
    | each {|f| $f | path dirname}
    | uniq
    | each {|d| if ($d | str starts-with "./") { $d } else { $"./($d)" } }
  )

  let tmp = (mktemp -d | path expand)
  try {
    ^git checkout-index --prefix=$"($tmp)/" -a
    cd $tmp
    ^go vet ...$pkgs
  } finally {
    ^rm -rf $tmp
  }
}
