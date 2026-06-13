// Package wiring provides shared bootstrap/wiring test helpers and neutral wiring
// fixtures for concern-split parity tests.
package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// FixtureBuildOpts mirrors wiring.BuildOpts for harness fixtures without
// importing wiring (avoids test import cycles).
type FixtureBuildOpts struct {
	FastAuth                bool
	SkipCrypto              bool
	SkipPeerTrust           bool
	SkipSignatureMiddleware bool
	OutboundOverride        *config.OutboundHTTPConfig
	SkipDiscoveryCache      bool
}

// HarnessWireOptions is the in-process integration harness baseline used by
// tests/integration/harness StartTestServerWithConfig.
var HarnessWireOptions = FixtureBuildOpts{
	FastAuth:                true,
	SkipCrypto:              true,
	SkipPeerTrust:           true,
	SkipSignatureMiddleware: true,
	OutboundOverride:        tshttp.HarnessOutboundConfig(),
	SkipDiscoveryCache:      true,
}

// ProductionWireOptions is the main.go zero-value bootstrap path.
var ProductionWireOptions = FixtureBuildOpts{}

// ExpectedCoreServicesOrder is the baseline for service construction and route
// mount order.
var ExpectedCoreServicesOrder = []string{
	"wellknown",
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// ExpectedAppServicesOrder is CoreServices minus the root service, preserving order.
var ExpectedAppServicesOrder = []string{
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// ExpectedRootService is the core service mounted at the host root.
const ExpectedRootService = "wellknown"

// ServiceUnprotectedPaths names a service and its default Unprotected() paths.
type ServiceUnprotectedPaths struct {
	Service string
	Paths   []string
}

// ExpectedUnprotectedSets captures default DevConfig Unprotected() declarations.
var ExpectedUnprotectedSets = []ServiceUnprotectedPaths{
	{Service: "wellknown", Paths: []string{
		"/.well-known/ocm", "/.well-known/ocm/", "/ocm-provider", "/ocm-provider/",
	}},
	{Service: "ocm", Paths: []string{"/shares", "/notifications", "/invite-accepted", "/token"}},
	{Service: "ocmaux", Paths: []string{"/federations", "/discover"}},
	{Service: "api", Paths: []string{"/healthz", "/auth/login"}},
	{Service: "ui", Paths: []string{"/login"}},
	{Service: "webdav", Paths: []string{"/ocm"}},
}
