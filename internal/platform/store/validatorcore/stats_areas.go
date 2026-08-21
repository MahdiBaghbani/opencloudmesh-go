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
	{Name: SpecificationAreaDiscovery, Grade: func(r StatsRaw) *string { return r.GradeDiscovery }},
	{Name: SpecificationAreaTLS, Grade: func(r StatsRaw) *string { return r.GradeTLS }},
	{Name: SpecificationAreaJWKS, Grade: func(r StatsRaw) *string { return r.GradeJWKS }},
	{Name: SpecificationAreaHTTPSig, Grade: func(r StatsRaw) *string { return r.GradeHTTPSig }},
	{Name: SpecificationAreaSharing, Grade: func(r StatsRaw) *string { return r.GradeSharing }},
	{Name: SpecificationAreaNotification, Grade: func(r StatsRaw) *string { return r.GradeNotification }},
	{Name: SpecificationAreaToken, Grade: func(r StatsRaw) *string { return r.GradeToken }},
	{Name: SpecificationAreaCapability, Grade: func(r StatsRaw) *string { return r.GradeCapability }},
}
