// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package repos provides an app-facing persistence seam that constructs the
// four OCM repository interfaces from a PersistenceConfig.
package repos

import (
	"strings"
	"time"
)

// permStringToSlice converts a comma-separated permissions string stored in
// the durable backend into the []string form used by app-layer models.
func permStringToSlice(s string) []string {
	if s == "" {
		return []string{}
	}

	return strings.Split(s, ",")
}

// permSliceToString converts a []string permissions slice into the
// comma-separated string stored in the durable backend.
func permSliceToString(perms []string) string {
	return strings.Join(perms, ",")
}

// unixToTime converts a Unix epoch (seconds) to time.Time in UTC.
func unixToTime(epoch int64) time.Time {
	if epoch == 0 {
		return time.Time{}
	}

	return time.Unix(epoch, 0).UTC()
}

// unixToTimePtr converts a Unix epoch to a *time.Time; returns nil when epoch
// is zero (the sentinel for "not set" used in durable stores).
func unixToTimePtr(epoch int64) *time.Time {
	if epoch == 0 {
		return nil
	}

	t := time.Unix(epoch, 0).UTC()

	return &t
}

// timeToUnix converts a time.Time to a Unix epoch (seconds).
func timeToUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}

// timePtrToUnix converts a *time.Time to a Unix epoch; returns 0 when nil.
func timePtrToUnix(t *time.Time) int64 {
	if t == nil {
		return 0
	}

	return t.Unix()
}

// int64PtrToInt64 converts a *int64 to int64; returns 0 when nil.
func int64PtrToInt64(v *int64) int64 {
	if v == nil {
		return 0
	}

	return *v
}

// int64ToInt64Ptr converts an int64 to *int64; returns nil when zero.
func int64ToInt64Ptr(v int64) *int64 {
	if v == 0 {
		return nil
	}

	return &v
}
