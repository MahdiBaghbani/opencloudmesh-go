// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"testing"

	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// strictProtocolTrustGroupFixtureJSON is the empty-directory-services trust-group
// fixture for VariantPeerTrustStaleMembership integration tests.
const strictProtocolTrustGroupFixtureJSON = `{
	"trustGroupId": "strict-protocol-pair",
	"enabled": true,
	"enforceMembership": false,
	"directoryServices": [],
	"keys": []
}`

func startStrictProtocolPair(t *testing.T) *harness.StrictProtocolPair {
	return startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantProtocolPair, nil)
}

func startStrictProtocolPairWithExtraAllowedPorts(
	t *testing.T,
	variant tsprotocol.Variant,
	extraAllowedPorts []int,
) *harness.StrictProtocolPair {
	t.Helper()

	moduleRoot := harness.FindProjectRoot(t)

	opts := harness.StrictProtocolPairStartOptions{
		ExtraAllowedPorts: extraAllowedPorts,
		TLSRootCAFile:     tsprotocol.StrictProtocolTLSRootCA(moduleRoot),
		ExtraConfigBuilder: func(allowedPorts []int, moduleRoot, loopbackHost string) string {
			return tsprotocol.StrictProtocolPairExtraConfig(tsprotocol.StrictProtocolPairExtraConfigOptions{
				ModuleRoot:   moduleRoot,
				LoopbackHost: loopbackHost,
				AllowedPorts: allowedPorts,
				Variant:      variant,
			})
		},
	}
	if variant == tsprotocol.VariantPeerTrustStaleMembership {
		opts.ExtraFiles = map[string]string{
			"trust-group.json": strictProtocolTrustGroupFixtureJSON,
		}
	}

	return harness.StartStrictProtocolPairWithOptions(t, opts)
}
