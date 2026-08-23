// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

// productionEntryIntegrationRel is the HTTP-only validator production-entry
// test. Existing callscan skips _test.go and misses method calls, so this
// file locks that boundary with a source-text scan of the integration test
// itself, not the production tree.
const productionEntryIntegrationRel = "tests/integration/validator_production_entry_test.go"

var productionEntryForbiddenTokens = []string{
	"MintOutgoingInvite",
	"CreateSessionProbeUser",
	"PartyRepo.Create",
	"ExtendToActive",
	"ReleaseActiveHardFail",
	"startActiveSession",
}

func TestValidatorProductionEntrySeams_RejectDirectProductionCalls(t *testing.T) {
	t.Parallel()

	root := modroot.ModuleRoot(t)
	path := filepath.Join(root, filepath.FromSlash(productionEntryIntegrationRel))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", productionEntryIntegrationRel, err)
	}

	body := string(data)
	if strings.TrimSpace(body) == "" {
		t.Fatalf("%s is empty", productionEntryIntegrationRel)
	}

	for _, token := range productionEntryForbiddenTokens {
		t.Run(token, func(t *testing.T) {
			t.Parallel()

			if strings.Contains(body, token) {
				t.Fatalf("%s must not appear in %s", token, productionEntryIntegrationRel)
			}
		})
	}
}
