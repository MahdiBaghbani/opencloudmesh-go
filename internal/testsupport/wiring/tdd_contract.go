package wiring

import (
	"path/filepath"
)

// MonolithParityTestRelPath is the deleted bootstrap parity monolith. Do not
// restore a monolithic bootstrap parity test outside internal/wiring.
const MonolithParityTestRelPath = "internal/wiring/bootstrap_parity_test.go"

// ParityConcernTestFiles lists concern-split parity test basenames under
// internal/wiring. Intentionally excludes skeleton_test.go (scaffold only, not
// bootstrap parity behavior).
var ParityConcernTestFiles = []string{
	"fixtures_parity_test.go",
	"options_parity_test.go",
	"crypto_parity_test.go",
	"peertrust_parity_test.go",
	"signature_middleware_parity_test.go",
	"discovery_cache_parity_test.go",
	"outbound_parity_test.go",
	"persistence_parity_test.go",
}

// FixtureRegistryIDs names exported wiring fixtures in testsupport/wiring.
var FixtureRegistryIDs = []string{
	"HarnessWireOptions",
	"ProductionWireOptions",
	"ExpectedCoreServicesOrder",
	"ExpectedAppServicesOrder",
	"ExpectedRootService",
	"ExpectedUnprotectedSets",
}

// WiringPackageRelPath is the composition-root package directory.
const WiringPackageRelPath = "internal/wiring"

// WiringDir joins module root with the wiring package path.
func WiringDir(moduleRoot string) string {
	return filepath.Join(moduleRoot, WiringPackageRelPath)
}
