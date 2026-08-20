// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// Closed retention-tier set and harvest-reason constants for permanent reports.
const (
	RetentionTierForever = "forever"
	RetentionTier7       = "7"
	RetentionTier14      = "14"
	RetentionTier30      = "30"
	RetentionTier60      = "60"
	RetentionTier90      = "90"

	// DefaultRetentionTier is applied at seal when a permanent report has no
	// chosen tier. It is independent of SessionConfig.TerminalRetentionDays.
	DefaultRetentionTier = RetentionTier30

	// HarvestReasonExpired is stamped on hard-expiry tombstones.
	HarvestReasonExpired = "retention_expired"

	SecondsPerDay = int64(86400)
)

const (
	retentionTierDays7  = 7
	retentionTierDays14 = 14
	retentionTierDays30 = 30
	retentionTierDays60 = 60
	retentionTierDays90 = 90
)

// RetentionTierDays maps a closed-set tier string to its day count.
// forever returns days=0 and forever=true. Any other string returns ok=false.
func RetentionTierDays(tier string) (days int, forever bool, ok bool) {
	switch tier {
	case RetentionTierForever:
		return 0, true, true
	case RetentionTier7:
		return retentionTierDays7, false, true
	case RetentionTier14:
		return retentionTierDays14, false, true
	case RetentionTier30:
		return retentionTierDays30, false, true
	case RetentionTier60:
		return retentionTierDays60, false, true
	case RetentionTier90:
		return retentionTierDays90, false, true
	default:
		return 0, false, false
	}
}

// ValidRetentionTier reports whether tier is one of the six closed-set strings.
func ValidRetentionTier(tier string) bool {
	_, _, ok := RetentionTierDays(tier)

	return ok
}

// PermanentOptedIn reports whether the row opted into a durable public report.
func PermanentOptedIn(row *TestRun) bool {
	return row != nil && row.OptInPermanent
}

// ReportExpired reports soft expiry for a permanent report. A stamped
// harvested_at wins even when expires_at is still in the future.
func ReportExpired(row *TestRun, now int64) bool {
	if !PermanentOptedIn(row) {
		return false
	}

	if row.HarvestedAt != nil {
		return true
	}

	return row.ExpiresAt != nil && now >= *row.ExpiresAt
}
