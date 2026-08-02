// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"net"
	"os"
	"testing"
)

// ResolveLoopbackHostname returns the machine hostname when it resolves to loopback.
func ResolveLoopbackHostname(t *testing.T) string {
	t.Helper()

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("hostname: %v", err)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(t.Context(), host)
	if err != nil {
		t.Fatalf("lookup %q: %v", host, err)
	}

	for _, addr := range addrs {
		if v4 := addr.IP.To4(); v4 != nil && v4[0] == 127 {
			return host
		}
	}

	t.Skipf("hostname %q does not resolve to an IPv4 address in 127.0.0.0/8", host)

	return host
}
