// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package invite provides helpers for OCM invite integration tests.
package invite

import (
	"path/filepath"
)

// StrictInstanceOptions tunes subprocess extra config for two-instance invite proofs.
type StrictInstanceOptions struct {
	ModuleRoot      string
	EnableWAYF      bool
	JSONPersistence bool
}

// StrictInstanceTLSRootCA returns the shared test CA bundle used by strict
// two-instance invite integration tests.
func StrictInstanceTLSRootCA(moduleRoot string) string {
	return filepath.Join(moduleRoot, "tests", "ca_pool", "testdata", "certificate-authority", "dockypody.crt")
}

// StrictInstanceExtraConfig returns TOML appended to the integration subprocess
// harness config. It mirrors tests/e2e/harness/server.ts strict settings.
// public_origin, listen_addr, outbound_http baseline, and tls_root_ca_file are
// owned by the harness SubprocessConfig fields.
func StrictInstanceExtraConfig(opts StrictInstanceOptions) string {
	tlsCert := filepath.Join(opts.ModuleRoot, "tests", "e2e", "testdata", "tls", "localhost.crt")
	tlsKey := filepath.Join(opts.ModuleRoot, "tests", "e2e", "testdata", "tls", "localhost.key")

	cfg := `
[tls]
mode = "static"
cert_file = "` + tlsCert + `"
key_file = "` + tlsKey + `"

[outbound_http.ssrf]
mode = "off"
`
	if opts.JSONPersistence {
		cfg += `
[persistence]
backend = "json"
data_dir = "data"
`
	}

	if opts.EnableWAYF {
		cfg += `
[http.services.ui.wayf]
enabled = true

[http.services.ui.invite_accept]
enabled = true
`
	}

	return cfg
}
