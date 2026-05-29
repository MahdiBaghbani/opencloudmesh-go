package service

import (
	"fmt"
	"sort"
	"sync"
)

// CoreServices lists service names always constructed (all registered today).
var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}

// RootService is the core service mounted at the host root rather than under
// external_base_path. Every other CoreServices entry is mounted as an app
// endpoint. This marker keeps route mounting derived from CoreServices instead
// of a separate hardcoded list.
const RootService = "wellknown"

// AppServices returns the core service names mounted under external_base_path,
// in CoreServices order, excluding RootService (mounted at the host root).
// Order is significant for Chi route matching, so it mirrors CoreServices.
func AppServices() []string {
	names := make([]string, 0, len(CoreServices))
	for _, name := range CoreServices {
		if name == RootService {
			continue
		}
		names = append(names, name)
	}
	return names
}

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

// CheckServiceNames validates names against the registered service set.
// It returns sorted unknown and allowed slices when any name is not registered,
// and nil, nil when all names are valid. Callers own nil-map guarding.
func CheckServiceNames(names []string) (unknown, allowed []string) {
	registered := RegisteredServices()
	allowedSet := make(map[string]struct{}, len(registered))
	for _, n := range registered {
		allowedSet[n] = struct{}{}
	}
	for _, name := range names {
		if _, ok := allowedSet[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil, nil
	}
	sort.Strings(unknown)
	sort.Strings(registered)
	return unknown, registered
}

// resetRegistry clears the registry (testing only).
func resetRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]NewService)
}
