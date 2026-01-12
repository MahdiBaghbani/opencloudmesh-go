// Package loader triggers service registration via blank imports.
// Import this package to ensure all services are registered with the registry.
package loader

// Import services here to trigger their init() registration.
// Services are added incrementally as they are migrated.
//
// Currently registered:
// - (none yet - wellknown and ocm added in later phases)
