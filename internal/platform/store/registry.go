package store

import (
	"fmt"
	"sync"
)

// DriverConfig holds configuration for driver selection and initialization.
type DriverConfig struct {
	// Driver is the driver name: json, sqlite, mirror
	Driver string `json:"driver"`

	// DataDir is the directory for data files (json files, sqlite db)
	DataDir string `json:"data_dir"`

	// Mirror configuration (only used when Driver == "mirror")
	Mirror MirrorConfig `json:"mirror"`
}

// MirrorConfig holds configuration for the sqlite+json mirror driver.
type MirrorConfig struct {
	// IncludeSecrets controls whether secrets are exported to JSON (default false)
	IncludeSecrets bool `json:"include_secrets"`

	// SecretsScope is the allowlist of secret types to export
	// Supported values: webdav_shared_secrets, session_tokens
	SecretsScope []string `json:"secrets_scope"`
}

// DriverFactory is a function that creates a driver instance.
type DriverFactory func(cfg *DriverConfig) (Driver, error)

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]DriverFactory)
)

// Register registers a driver factory by name.
// This is typically called from init() in driver packages.
func Register(name string, factory DriverFactory) {
	driversMu.Lock()
	defer driversMu.Unlock()
	drivers[name] = factory
}

// New creates a driver instance based on the configuration.
func New(cfg *DriverConfig) (Driver, error) {
	driversMu.RLock()
	factory, ok := drivers[cfg.Driver]
	driversMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown driver: %s", cfg.Driver)
	}

	return factory(cfg)
}

// AvailableDrivers returns the list of registered driver names.
func AvailableDrivers() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()

	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}
	return names
}
