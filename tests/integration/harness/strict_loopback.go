// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

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
	ips, err := net.LookupIP(host)
	if err != nil {
		t.Fatalf("lookup %q: %v", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && v4[0] == 127 {
			return host
		}
	}
	t.Skipf("hostname %q does not resolve to an IPv4 address in 127.0.0.0/8", host)
	return host
}
