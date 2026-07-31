// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestDiscoveryCacheSkip_WiresClient(t *testing.T) {
	t.Run("SkipDiscoveryCache=true wires NoopCache to discovery client", func(t *testing.T) {
		result, err := wiring.Build(
			config.DevConfig(),
			tslog.DiscardLogger(),
			harnessBuildOpts(),
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		d := result.Deps
		if !d.DiscoveryClient.IsNoopCache() {
			t.Error("expected NoopCache when SkipDiscoveryCache=true, got a different cache")
		}

		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil even when SkipDiscoveryCache=true")
		}
	})

	t.Run("SkipDiscoveryCache=false wires shared cache to discovery client", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.SkipDiscoveryCache = false

		result, err := wiring.Build(
			config.DevConfig(),
			tslog.DiscardLogger(),
			opts,
		)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		d := result.Deps
		if d.DiscoveryClient.IsNoopCache() {
			t.Error("discovery client must not use NoopCache when SkipDiscoveryCache=false")
		}

		if d.Cache == nil {
			t.Fatal("Deps.Cache must be non-nil when SkipDiscoveryCache=false")
		}
	})
}
