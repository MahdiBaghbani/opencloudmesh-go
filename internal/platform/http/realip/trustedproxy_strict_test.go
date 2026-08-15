// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import (
	"net"
	"testing"
)

func TestNewTrustedProxiesStrict_RejectsInvalid(t *testing.T) {
	t.Parallel()

	_, err := NewTrustedProxiesStrict([]string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid trusted proxy")
	}
}

func TestNewTrustedProxiesStrict_SingleIP(t *testing.T) {
	t.Parallel()

	tp, err := NewTrustedProxiesStrict([]string{"192.168.1.1"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	if !tp.IsTrusted(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be trusted")
	}

	if tp.IsTrusted(net.ParseIP("192.168.1.2")) {
		t.Error("expected 192.168.1.2 to not be trusted")
	}
}
