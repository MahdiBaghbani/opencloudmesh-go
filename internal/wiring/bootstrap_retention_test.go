// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestStartRetentionSweep_StopJoinsGoroutine(t *testing.T) {
	t.Parallel()

	stop := startRetentionSweep(&validatorcore.Core{})
	if stop == nil {
		t.Fatal("expected stop func for non-nil store")
	}

	done := make(chan struct{})

	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startRetentionSweep stop func did not return after cancel")
	}

	stop()
}
