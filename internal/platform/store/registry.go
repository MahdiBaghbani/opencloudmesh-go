// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import (
	"fmt"
	"strings"
	"sync"
)

// DriverConfig holds configuration for driver selection and initialization.
type DriverConfig struct {
	// Driver is the driver name: memory, json, sqlite, mirror
	Driver string `json:"driver"`

	// DataDir is the directory for data files (json files, sqlite db)
	DataDir string `json:"dataDir"`
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
	if factory == nil {
		panic("store: nil driver factory")
	}

	if strings.TrimSpace(name) == "" {
		panic("store: empty driver name")
	}

	driversMu.Lock()
	defer driversMu.Unlock()

	drivers[name] = factory
}

// Unregister removes a driver factory by name. Intended for test isolation.
func Unregister(name string) {
	driversMu.Lock()
	defer driversMu.Unlock()

	delete(drivers, name)
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
