package service

import (
	"log/slog"
	"net/http"
	"slices"
	"testing"
)

// mockService is a minimal Service implementation for testing.
type mockService struct{}

func (m *mockService) Handler() http.Handler  { return nil }
func (m *mockService) Prefix() string         { return "mock" }
func (m *mockService) Close() error           { return nil }
func (m *mockService) Unprotected() []string  { return nil }

// mockNewService is a constructor that creates a mockService.
func mockNewService(conf map[string]any, log *slog.Logger) (Service, error) {
	return &mockService{}, nil
}

func TestRegister(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	err := Register("test-service", mockNewService)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify it was registered
	constructor := Get("test-service")
	if constructor == nil {
		t.Fatal("Get returned nil for registered service")
	}
}

func TestRegister_Duplicate(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	err := Register("dup-service", mockNewService)
	if err != nil {
		t.Fatalf("First Register failed: %v", err)
	}

	// Second registration should fail
	err = Register("dup-service", mockNewService)
	if err == nil {
		t.Fatal("Expected error on duplicate registration, got nil")
	}
}

func TestMustRegister_Panics(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	// First registration should not panic
	MustRegister("panic-test", mockNewService)

	// Second registration should panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected panic on duplicate MustRegister, got none")
		}
	}()
	MustRegister("panic-test", mockNewService)
}

func TestGet_NotRegistered(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	constructor := Get("nonexistent")
	if constructor != nil {
		t.Fatal("Expected nil for unregistered service")
	}
}

// TestAppServicesParity guards the core-service parity contract: the root
// service plus the app services must exactly reconstruct CoreServices, in
// order. This prevents silent drift between service construction and route
// mounting when a core service is added, removed, or renamed.
func TestAppServicesParity(t *testing.T) {
	// RootService must be a member of CoreServices.
	if !slices.Contains(CoreServices, RootService) {
		t.Fatalf("RootService %q is not present in CoreServices %v", RootService, CoreServices)
	}

	app := AppServices()

	// AppServices must never include the root service.
	if slices.Contains(app, RootService) {
		t.Errorf("AppServices() must not include RootService %q, got %v", RootService, app)
	}

	// Reconstructing CoreServices from RootService + AppServices, preserving
	// CoreServices order, must match exactly (no dropped or extra services).
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

	// Every core service must be accounted for: root or app, no overlap.
	if len(app)+1 != len(CoreServices) {
		t.Errorf("AppServices() length %d + 1 root != CoreServices length %d", len(app), len(CoreServices))
	}
}

func TestRegisteredServices(t *testing.T) {
	resetRegistry()
	defer resetRegistry()

	Register("svc-a", mockNewService)
	Register("svc-b", mockNewService)
	Register("svc-c", mockNewService)

	names := RegisteredServices()
	if len(names) != 3 {
		t.Fatalf("Expected 3 services, got %d", len(names))
	}

	// Check all names are present (order is not guaranteed)
	slices.Sort(names)
	expected := []string{"svc-a", "svc-b", "svc-c"}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("Expected %s at index %d, got %s", name, i, names[i])
		}
	}
}
