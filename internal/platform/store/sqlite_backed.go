// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import "gorm.io/gorm"

// SQLiteBacked is implemented by persistence drivers that open a single shared
// GORM/SQLite handle (sqlite and mirror backends).
type SQLiteBacked interface {
	Driver
	SharedDB() *gorm.DB
}
