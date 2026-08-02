// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package wiring provides shared bootstrap/wiring test helpers and neutral wiring
// fixtures for concern-split parity tests.
package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
)

// FixtureBuildOpts mirrors wiring.BuildOpts for harness fixtures without
// importing wiring (avoids test import cycles).
type FixtureBuildOpts struct {
	FastAuth           bool
	SkipCrypto         bool
	SkipPeerTrust      bool
	OutboundOverride   *config.OutboundHTTPConfig
	SkipDiscoveryCache bool
}

// HarnessWireOptions is the in-process integration harness baseline used by
// tests/integration/harness StartTestServerWithConfig. Crypto and signature
// middleware match production; remaining skips are test transport shortcuts.
var HarnessWireOptions = FixtureBuildOpts{
	FastAuth:           true,
	SkipCrypto:         false,
	SkipPeerTrust:      true,
	OutboundOverride:   tshttp.HarnessOutboundConfig(),
	SkipDiscoveryCache: true,
}

// IETFWireOptions is the IETF strict signature fixture after harness
// convergence: real crypto and signature middleware enabled (SkipCrypto
// false). See harness.IETFIntegrationBuildOpts.
var IETFWireOptions = FixtureBuildOpts{
	FastAuth:           true,
	SkipCrypto:         false,
	SkipPeerTrust:      true,
	OutboundOverride:   tshttp.HarnessOutboundConfig(),
	SkipDiscoveryCache: true,
}

// ProductionWireOptions is the main.go zero-value bootstrap path.
var ProductionWireOptions = FixtureBuildOpts{}

// ExpectedRouteOpts captures default DevConfig route-policy inputs.
var ExpectedRouteOpts = tsrouting.DevOpts()

// ExpectedPublicSessionPaths lists default DevConfig public session paths from
// the route-policy aggregate.
var ExpectedPublicSessionPaths = tsrouting.PublicSessionPaths(ExpectedRouteOpts)

// RouteOptsForConfig derives route opts the same way the HTTP server does.
func RouteOptsForConfig(cfg *config.Config) service.RouteOpts {
	return service.RouteOptsFromConfig(cfg)
}
