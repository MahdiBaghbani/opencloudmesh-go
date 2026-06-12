package wiring

import (
	"path/filepath"
)

// MonolithParityTestRelPath is the deleted bootstrap parity monolith. Do not
// restore a monolithic bootstrap parity test outside internal/wiring.
const MonolithParityTestRelPath = "internal/wiring/bootstrap_parity_test.go"

// ParityConcernTestFiles lists build concern test basenames under
// internal/wiring. Intentionally excludes skeleton_test.go (scaffold only, not
// bootstrap parity behavior).
var ParityConcernTestFiles = []string{
	"build_fixtures_test.go",
	"build_options_test.go",
	"build_crypto_test.go",
	"build_peertrust_test.go",
	"build_signature_middleware_test.go",
	"build_discovery_cache_test.go",
	"build_outbound_test.go",
	"build_persistence_test.go",
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
