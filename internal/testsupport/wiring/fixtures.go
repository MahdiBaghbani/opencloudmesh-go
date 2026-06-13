// Package wiring provides shared bootstrap/wiring test helpers and neutral wiring
// fixtures for concern-split parity tests.
package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
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

// ServiceUnprotectedPaths names a service and its default Unprotected() paths.
type ServiceUnprotectedPaths struct {
	Service string
	Paths   []string
}

// unprotectedPathExpectations holds default DevConfig Unprotected() path lists
// keyed by descriptor service name. Service names and order come from
// service.Descriptors().
var unprotectedPathExpectations = map[string][]string{
	"wellknown": {
		"/.well-known/ocm", "/.well-known/ocm/", "/ocm-provider", "/ocm-provider/",
	},
	"ocm":    {"/shares", "/notifications", "/invite-accepted", "/token"},
	"ocmaux": {"/federations", "/discover"},
	"api":    {"/healthz", "/auth/login"},
	"ui":     {"/login"},
	"webdav": {"/ocm"},
}

// ExpectedUnprotectedSets captures default DevConfig Unprotected() declarations
// in descriptor order.
var ExpectedUnprotectedSets = buildExpectedUnprotectedSets()

func buildExpectedUnprotectedSets() []ServiceUnprotectedPaths {
	descs := service.Descriptors()
	out := make([]ServiceUnprotectedPaths, 0, len(descs))
	seen := make(map[string]struct{}, len(descs))
	for _, d := range descs {
		paths, ok := unprotectedPathExpectations[d.Name]
		if !ok {
			panic("missing unprotected path expectations for descriptor " + d.Name)
		}
		seen[d.Name] = struct{}{}
		out = append(out, ServiceUnprotectedPaths{
			Service: d.Name,
			Paths:   paths,
		})
	}
	for name := range unprotectedPathExpectations {
		if _, ok := seen[name]; !ok {
			panic("stale unprotected path expectations for removed descriptor " + name)
		}
	}
	return out
}
