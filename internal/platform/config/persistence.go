// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

// Persistence backend name constants. These are the only valid values for
// PersistenceConfig.Backend. Unknown values are rejected at validation time;
// there is no silent fallback to memory.
const (
	BackendMemory = "memory"
	BackendJSON   = "json"
	BackendSQLite = "sqlite"
	BackendMirror = "mirror"
)

// DefaultPersistenceDataDir is the CWD-relative data directory the strict
// preset uses for its durable sqlite backend.
const DefaultPersistenceDataDir = ".ocm/data"
