// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// DeriveHealthy reports whether a stats snapshot is healthy from its grade
// columns. healthy iff no non-NULL grade is warn or fail (NULL is unassessed and
// ignored). All-NULL grades are not healthy.
func DeriveHealthy(raw StatsRaw) bool {
	grades := []*string{
		raw.GradeDiscovery,
		raw.GradeTLS,
		raw.GradeJWKS,
		raw.GradeHTTPSig,
		raw.GradeSharing,
		raw.GradeNotification,
		raw.GradeToken,
		raw.GradeCapability,
	}

	anyAssessed := false

	for _, grade := range grades {
		if grade == nil {
			continue
		}

		anyAssessed = true

		switch *grade {
		case GradeWarn, GradeFail:
			return false
		}
	}

	return anyAssessed
}

// DeriveHealthySnapshot is DeriveHealthy for an in-memory StatsSnapshot.
func DeriveHealthySnapshot(snapshot StatsSnapshot) bool {
	return DeriveHealthy(snapshot.ToStatsRaw())
}
