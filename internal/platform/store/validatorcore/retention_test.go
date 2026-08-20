// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "testing"

func TestRetentionTierDays_AcceptsClosedSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		tier    string
		days    int
		forever bool
	}{
		{name: "forever", tier: RetentionTierForever, forever: true},
		{name: "7", tier: RetentionTier7, days: 7},
		{name: "14", tier: RetentionTier14, days: 14},
		{name: "30", tier: RetentionTier30, days: 30},
		{name: "60", tier: RetentionTier60, days: 60},
		{name: "90", tier: RetentionTier90, days: 90},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			days, forever, ok := RetentionTierDays(tc.tier)
			if !ok {
				t.Fatalf("RetentionTierDays(%q) ok = false, want true", tc.tier)
			}

			if days != tc.days {
				t.Fatalf("RetentionTierDays(%q) days = %d, want %d", tc.tier, days, tc.days)
			}

			if forever != tc.forever {
				t.Fatalf("RetentionTierDays(%q) forever = %v, want %v", tc.tier, forever, tc.forever)
			}

			if !ValidRetentionTier(tc.tier) {
				t.Fatalf("ValidRetentionTier(%q) = false, want true", tc.tier)
			}
		})
	}
}

func TestRetentionTierDays_RejectsUnknown(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tier string
	}{
		{name: "empty", tier: ""},
		{name: "1", tier: "1"},
		{name: "365", tier: "365"},
		{name: "Forever", tier: "Forever"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			days, forever, ok := RetentionTierDays(tc.tier)
			if ok || days != 0 || forever {
				t.Fatalf("RetentionTierDays(%q) = (%d, %v, %v), want (0, false, false)",
					tc.tier, days, forever, ok)
			}

			if ValidRetentionTier(tc.tier) {
				t.Fatalf("ValidRetentionTier(%q) = true, want false", tc.tier)
			}
		})
	}
}

func TestReportExpired(t *testing.T) {
	t.Parallel()

	expires := int64(1000)
	future := int64(2000)
	harvested := int64(50)

	cases := []struct {
		name string
		row  *TestRun
		now  int64
		want bool
	}{
		{name: "nil row", now: expires, want: false},
		{
			name: "not opted in",
			row:  &TestRun{ExpiresAt: &expires},
			now:  expires,
			want: false,
		},
		{
			name: "now equals expires_at",
			row:  &TestRun{OptInPermanent: true, ExpiresAt: &expires},
			now:  expires,
			want: true,
		},
		{
			name: "harvested_at wins over future expires_at",
			row: &TestRun{
				OptInPermanent: true,
				ExpiresAt:      &future,
				HarvestedAt:    &harvested,
			},
			now:  expires,
			want: true,
		},
		{
			name: "forever not expired",
			row:  &TestRun{OptInPermanent: true},
			now:  expires,
			want: false,
		},
		{
			name: "before expires_at",
			row:  &TestRun{OptInPermanent: true, ExpiresAt: &expires},
			now:  expires - 1,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := ReportExpired(tc.row, tc.now); got != tc.want {
				t.Fatalf("ReportExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPermanentOptedIn_NilSafe(t *testing.T) {
	t.Parallel()

	if PermanentOptedIn(nil) {
		t.Fatal("PermanentOptedIn(nil) = true, want false")
	}

	if PermanentOptedIn(&TestRun{}) {
		t.Fatal("PermanentOptedIn(opt-out) = true, want false")
	}

	if !PermanentOptedIn(&TestRun{OptInPermanent: true}) {
		t.Fatal("PermanentOptedIn(opt-in) = false, want true")
	}
}
