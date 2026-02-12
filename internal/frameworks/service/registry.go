package service

import (
	"fmt"
	"sync"
)

// CoreServices lists service names always constructed (all registered today).
var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]NewService)
)

// Register registers an HTTP service constructor by name. Typically called from init().
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
func MustRegister(name string, newFunc NewService) {
	if err := Register(name, newFunc); err != nil {
		panic(err)
	}
}

// Get returns the constructor for a registered service, or nil if unknown.
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

// resetRegistry clears the registry (testing only).
func resetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]NewService)
}
