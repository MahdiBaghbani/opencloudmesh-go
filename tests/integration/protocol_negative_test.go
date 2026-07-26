// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"testing"

	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
)

// Unit-primary negative tiers are not re-proved here in subprocess integration:
//   - non-Bearer credential: internal/components/webdav/webdav_test.go TestServeHTTP_BasicAuthRejected401
//   - expired exchanged token: internal/components/webdav/webdav_test.go TestServeHTTP_BearerWithExpiredTokenFails401
//   - oversized body: internal/services/ocm/ocm_active_routes_test.go TestOCMRequestBodyLimit
//   - stale trust membership refresh: internal/components/ocm/peertrust/membership_test.go

// TestProtocolNegativeStrict exercises strict subprocess rejection classes with
// persistence, network, fallback, and log invariants.
func TestProtocolNegativeStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	t.Run("inbound", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantProtocolPair,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)

		runInboundNegativeCases(t, pair, recordingReceiver)
	})

	t.Run("outbound_cross_authority_endpoint", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		receiver := startCrossAuthorityDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}

		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantProtocolPair, extraPorts)
		defer pair.Stop(t)

		runOutboundCrossAuthorityCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("outbound_redirect_ssrf", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		receiver := startRedirectSSRFDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}

		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantSSRFStrictRedirect, extraPorts)
		defer pair.Stop(t)

		runOutboundRedirectSSRFCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("outbound_stale_trust_membership", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantPeerTrustStaleMembership,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)

		runOutboundStaleTrustMembershipCase(t, pair, recordingReceiver)
	})

	t.Run("contract_malformed_discovery_blocks_outbound_post", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		receiver := startMalformedDiscoveryPeer(t)
		extraPorts := []int{receiver.Port(), strictRecordingReceiverAllowedPort(t, recordingReceiver)}

		pair := startStrictProtocolPairWithExtraAllowedPorts(t, tsprotocol.VariantProtocolPair, extraPorts)
		defer pair.Stop(t)

		runMalformedDiscoveryBlocksOutboundCase(t, pair, receiver, recordingReceiver)
	})

	t.Run("contract_unexchanged_shared_secret_bearer_401", func(t *testing.T) {
		recordingReceiver := startStrictRecordingReceiver(t)
		defer recordingReceiver.Close()

		pair := startStrictProtocolPairWithExtraAllowedPorts(
			t,
			tsprotocol.VariantProtocolPair,
			[]int{strictRecordingReceiverAllowedPort(t, recordingReceiver)},
		)
		defer pair.Stop(t)

		runUnexchangedSharedSecretBearer401Case(t, pair, recordingReceiver)
	})
}
