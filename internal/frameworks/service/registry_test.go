// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"slices"
	"testing"
)

// TestAppServicesMatchCoreServicesMinusRoot verifies the root service plus app
// services exactly reconstruct CoreServices in order. This prevents silent drift
// when the core service set changes.
func TestAppServicesMatchCoreServicesMinusRoot(t *testing.T) {
	if !slices.Contains(CoreServices, RootService) {
		t.Fatalf("RootService %q is not present in CoreServices %v", RootService, CoreServices)
	}

	app := AppServices()

	if slices.Contains(app, RootService) {
		t.Errorf("AppServices() must not include RootService %q, got %v", RootService, app)
	}

	want := make([]string, 0, len(CoreServices))
	for _, name := range CoreServices {
		if name == RootService {
			continue
		}

		want = append(want, name)
	}

	if !slices.Equal(app, want) {
		t.Errorf("AppServices() = %v, want %v (CoreServices order minus RootService)", app, want)
	}

	if len(app)+1 != len(CoreServices) {
		t.Errorf("AppServices() length %d + 1 root != CoreServices length %d", len(app), len(CoreServices))
	}
}

// TestDescriptorsDerivedViews verifies CoreServices stay aligned with the
// canonical descriptor table.
func TestDescriptorsDerivedViews(t *testing.T) {
	assertDescriptorsMatchCoreServicesMetadata(t)
}

func TestCheckServiceNames(t *testing.T) {
	t.Run("all valid", func(t *testing.T) {
		unknown, allowed := CheckServiceNames(CoreServices)
		if unknown != nil {
			t.Fatalf("unknown = %v, want nil", unknown)
		}

		if allowed != nil {
			t.Fatalf("allowed = %v, want nil", allowed)
		}
	})

	t.Run("unknown names rejected", func(t *testing.T) {
		names := []string{"ocm", "bogus", "api", "also-bad"}

		unknown, allowed := CheckServiceNames(names)
		if !slices.Equal(unknown, []string{"also-bad", "bogus"}) {
			t.Fatalf("unknown = %v, want sorted [also-bad bogus]", unknown)
		}

		if !slices.Equal(allowed, CoreServices) {
			t.Fatalf("allowed = %v, want CoreServices %v", allowed, CoreServices)
		}
	})
}
