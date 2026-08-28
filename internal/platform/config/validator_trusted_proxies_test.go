// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config_test

import (
	"net"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

func TestDefaultValidatorTrustedProxies_AcceptedByStrict(t *testing.T) {
	t.Parallel()

	tp, err := realip.NewTrustedProxiesStrict(config.DefaultValidatorTrustedProxies)
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	if !tp.IsTrusted(net.ParseIP("172.17.0.2")) {
		t.Error("expected docker bridge address 172.17.0.2 to be trusted")
	}
}
