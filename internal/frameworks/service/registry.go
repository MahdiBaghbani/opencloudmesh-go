package service

import (
	"fmt"
	"sync"
)

// CoreServices lists service names that are always constructed regardless of
// whether [http.services.<name>] appears in TOML. Today all registered
// services are core; the variable exists so future optional services can
// register without being added here.
var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]NewService)
)

// Register registers a new HTTP service constructor by name.
// This is typically called from init() in service packages.
// Duplicate registration returns an error (fail-fast, no panic).
func Register(name string, newFunc NewService) error {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		return fmt.Errorf("service %q already registered", name)
	}
	registry[name] = newFunc
	return nil
}

// MustRegister is like Register but panics on error.
// Use this in init() where returning an error is not possible.
func MustRegister(name string, newFunc NewService) {
	if err := Register(name, newFunc); err != nil {
		panic(err)
	}
}

// Get returns the constructor for a registered service.
// Returns nil if the service is not registered.
func Get(name string) NewService {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[name]
}

// RegisteredServices returns the names of all registered services.
func RegisteredServices() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// resetRegistry is for testing only. Clears the registry.
func resetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]NewService)
}
