package service

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// snapshotCoreServicesOrder is the Q5 T0 baseline for service construction and
// route mount order. Update only when intentionally changing CoreServices.
var snapshotCoreServicesOrder = []string{
	"wellknown",
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

// snapshotAppServicesOrder is CoreServices minus the root service, preserving order.
var snapshotAppServicesOrder = []string{
	"ocm",
	"ocmaux",
	"api",
	"ui",
	"webdav",
}

func TestBehaviorSnapshot_CoreServicesOrder(t *testing.T) {
	if !slices.Equal(CoreServices, snapshotCoreServicesOrder) {
		t.Fatalf("CoreServices = %v, want snapshot %v", CoreServices, snapshotCoreServicesOrder)
	}
}

func TestBehaviorSnapshot_RootService(t *testing.T) {
	if RootService != "wellknown" {
		t.Fatalf("RootService = %q, want %q", RootService, "wellknown")
	}
}

func TestBehaviorSnapshot_AppServicesOrder(t *testing.T) {
	got := AppServices()
	if !slices.Equal(got, snapshotAppServicesOrder) {
		t.Fatalf("AppServices() = %v, want snapshot %v", got, snapshotAppServicesOrder)
	}
}

func TestBehaviorSnapshot_CoreServicesRegistrySourceAnchor(t *testing.T) {
	root := moduleRootForSnapshot(t)
	registryPath := filepath.Join(root, "internal/frameworks/service/registry.go")
	body, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatalf("read registry.go: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}`,
		`const RootService = "wellknown"`,
		`func AppServices() []string {`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("registry.go anchor missing %q", needle)
		}
	}
}

func moduleRootForSnapshot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}
