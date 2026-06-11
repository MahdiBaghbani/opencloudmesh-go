// Package wiringtest provides shared bootstrap/wiring test helpers and Q5 T0
// snapshot fixtures for concern-split parity tests.
package wiringtest

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// SnapshotHarnessWireOptions is the in-process integration harness baseline from
// tests/integration/harness/harness.go StartTestServerWithConfig.
var SnapshotHarnessWireOptions = app.WireOptions{
	FastAuth:                true,
	SkipCrypto:              true,
	SkipPeerTrust:           true,
	SkipSignatureMiddleware: true,
	OutboundOverride: &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		SSRFMode:           "off",
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true,
	},
	SkipDiscoveryCache: true,
}

// SnapshotHarnessWireOptionsSourceNeedles are substring anchors in
// tests/integration/harness/harness.go StartTestServerWithConfig bootstrap.
// Keep in sync with tests/integration/harness/behavior_snapshot_test.go.
var SnapshotHarnessWireOptionsSourceNeedles = []string{
	`app.BootstrapDeps(cfg, logger, app.WireOptions{`,
	`FastAuth:                true,`,
	`SkipCrypto:              true,`,
	`SkipPeerTrust:           true,`,
	`SkipSignatureMiddleware: true,`,
	`SSRF:               config.SSRFConfig{Mode: "off"},`,
	`SSRFMode:           "off",`,
	`TimeoutMS:          5000,`,
	`ConnectTimeoutMS:   2000,`,
	`MaxRedirects:       1,`,
	`MaxResponseBytes:   1048576,`,
	`InsecureSkipVerify: true,`,
	`SkipDiscoveryCache: true,`,
}

// SnapshotProductionWireOptions is the main.go zero-value bootstrap path.
var SnapshotProductionWireOptions = app.WireOptions{}

// SnapshotCoreServicesOrder is the Q5 T0 baseline for service construction and
// route mount order.
var SnapshotCoreServicesOrder = []string{
	"wellknown",
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// SnapshotAppServicesOrder is CoreServices minus the root service, preserving order.
var SnapshotAppServicesOrder = []string{
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// SnapshotRootService is the Q5 T0 baseline root mount service name.
const SnapshotRootService = "wellknown"

// UnprotectedSnapshot names a service and its default Unprotected() paths.
type UnprotectedSnapshot struct {
	Service string
	Paths   []string
}

// SnapshotUnprotectedSets captures default DevConfig Unprotected() declarations.
var SnapshotUnprotectedSets = []UnprotectedSnapshot{
	{Service: "wellknown", Paths: []string{
		"/.well-known/ocm", "/.well-known/ocm/", "/ocm-provider", "/ocm-provider/",
	}},
	{Service: "ocm", Paths: []string{"/shares", "/notifications", "/invite-accepted", "/token"}},
	{Service: "ocmaux", Paths: []string{"/federations", "/discover"}},
	{Service: "api", Paths: []string{"/healthz", "/auth/login"}},
	{Service: "ui", Paths: []string{"/login"}},
	{Service: "webdav", Paths: []string{"/ocm"}},
}
