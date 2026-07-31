// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"slices"
	"testing"
)

func assertDescriptorsMatchCoreServicesMetadata(t *testing.T) {
	t.Helper()

	descs := Descriptors()
	if len(descs) != len(CoreServices) {
		t.Fatalf("descriptor count = %d, want CoreServices length %d", len(descs), len(CoreServices))
	}

	names := make([]string, len(descs))
	rootCount := 0

	for i, d := range descs {
		names[i] = d.Name
		if d.Build == "" {
			t.Errorf("descriptor %q has no build key", d.Name)
		}

		if d.MountAtRoot {
			rootCount++

			if d.Name != RootService {
				t.Errorf("MountAtRoot service = %q, want RootService %q", d.Name, RootService)
			}
		}

		if d.Prefix != "" && d.MountAtRoot {
			t.Errorf("descriptor %q is MountAtRoot but has prefix %q", d.Name, d.Prefix)
		}
	}

	if !slices.Equal(names, CoreServices) {
		t.Errorf("descriptor names = %v, want CoreServices %v", names, CoreServices)
	}

	if rootCount != 1 {
		t.Fatalf("MountAtRoot descriptor count = %d, want 1", rootCount)
	}
}
