// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// setRunState moves the run directly, simulating another writer.
func (e *testEnv) setRunState(t *testing.T, runID, state string) {
	t.Helper()

	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Updates(map[string]any{"state": state, "updated_at": time.Now().Unix()}).Error; err != nil {
		t.Fatalf("set run state: %v", err)
	}
}

func createProbeFile(t *testing.T) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("/tmp", "forward-probe-*")
	if err != nil {
		t.Fatalf("create probe file: %v", err)
	}

	path := tmpFile.Name()

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close probe file: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove probe file: %v", err)
		}
	})

	return path
}

// stubResolver implements the handler's PeerFactsResolver without touching
// the peer-mapping config surface.
type stubResolver struct {
	facts policy.Facts
}

func (r *stubResolver) ResolveFacts(_ string) policy.Facts {
	return r.facts
}
