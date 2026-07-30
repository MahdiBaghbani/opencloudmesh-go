# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

# Shared context loader for action-pin helpers.

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

# Load repo root, action-pins manifest, and sorted workflow paths (*.yml + *.yaml).
# Fails non-zero when no workflow files match.
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
  {
    root: $root
    manifest_path: $manifest_path
    manifest: $manifest
    workflows_dir: $workflows_dir
    workflow_paths: $workflow_paths
  }
}
