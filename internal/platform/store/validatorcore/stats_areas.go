// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// statsAreaSpec maps a public statistics area name to a grade column accessor.
type statsAreaSpec struct {
	Name  string
	Grade func(StatsRaw) *string
}

// statsAreaOrder is the stable public ordering for area aggregates.
var statsAreaOrder = []statsAreaSpec{
	{Name: "discovery", Grade: func(r StatsRaw) *string { return r.GradeDiscovery }},
	{Name: "tls", Grade: func(r StatsRaw) *string { return r.GradeTLS }},
	{Name: "jwks", Grade: func(r StatsRaw) *string { return r.GradeJWKS }},
	{Name: "httpsig", Grade: func(r StatsRaw) *string { return r.GradeHTTPSig }},
	{Name: "sharing", Grade: func(r StatsRaw) *string { return r.GradeSharing }},
	{Name: "notification", Grade: func(r StatsRaw) *string { return r.GradeNotification }},
	{Name: "token", Grade: func(r StatsRaw) *string { return r.GradeToken }},
	{Name: "capability", Grade: func(r StatsRaw) *string { return r.GradeCapability }},
}
