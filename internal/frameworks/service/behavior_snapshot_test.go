package service

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"
)

func TestBehaviorSnapshot_CoreServicesOrder(t *testing.T) {
	if !slices.Equal(CoreServices, wiringtest.SnapshotCoreServicesOrder) {
		t.Fatalf("CoreServices = %v, want snapshot %v", CoreServices, wiringtest.SnapshotCoreServicesOrder)
	}
}

func TestBehaviorSnapshot_RootService(t *testing.T) {
	if RootService != wiringtest.SnapshotRootService {
		t.Fatalf("RootService = %q, want %q", RootService, wiringtest.SnapshotRootService)
	}
}

func TestBehaviorSnapshot_AppServicesOrder(t *testing.T) {
	got := AppServices()
	if !slices.Equal(got, wiringtest.SnapshotAppServicesOrder) {
		t.Fatalf("AppServices() = %v, want snapshot %v", got, wiringtest.SnapshotAppServicesOrder)
	}
}

func TestBehaviorSnapshot_CoreServicesRegistrySourceAnchor(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
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
