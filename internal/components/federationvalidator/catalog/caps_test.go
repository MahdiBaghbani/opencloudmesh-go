// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package catalog

import "testing"

func TestCaps_ReverseInviteAvailable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		caps Caps
		want bool
	}{
		{name: "empty", caps: Caps{}},
		{name: "runner only", caps: Caps{Runner: true}},
		{
			name: "missing reverse share",
			caps: Caps{Runner: true, ReverseInvite: true, ForwardShare: true},
		},
		{
			name: "full reverse invite path",
			caps: Caps{
				Runner:        true,
				ReverseInvite: true,
				ForwardShare:  true,
				ReverseShare:  true,
			},
			want: true,
		},
		{
			name: "full caps",
			caps: FullCaps(),
			want: true,
		},
		{
			name: "abort does not imply reverse invite",
			caps: Caps{Abort: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.caps.ReverseInviteAvailable(); got != tc.want {
				t.Fatalf("ReverseInviteAvailable() = %v, want %v", got, tc.want)
			}
		})
	}
}
