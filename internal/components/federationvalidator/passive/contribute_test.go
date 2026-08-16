// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"testing"
)

func TestParseContribute(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "1", want: true},
		{raw: "", want: false},
		{raw: "0", want: false},
		{raw: " 1", want: false},
		{raw: "1 ", want: false},
		{raw: " 1 ", want: false},
		{raw: "+1", want: false},
		{raw: "true", want: false},
		{raw: "yes", want: false},
		{raw: "01", want: false},
	}

	for _, tc := range cases {
		if got := ParseContribute(tc.raw); got != tc.want {
			t.Fatalf("ParseContribute(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
