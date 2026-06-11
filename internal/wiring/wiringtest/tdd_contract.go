package wiringtest

import (
	"path/filepath"
)

// MonolithParityTestRelPath is the deleted bootstrap parity monolith. T1 must not
// restore it under internal/platform/app.
const MonolithParityTestRelPath = "internal/platform/app/bootstrap_parity_test.go"

// ParityConcernTestFiles lists concern-split parity test basenames under
// internal/wiring. Intentionally excludes skeleton_test.go (T1 scaffold, not
// bootstrap parity behavior).
var ParityConcernTestFiles = []string{
	"snapshots_parity_test.go",
	"options_parity_test.go",
	"crypto_parity_test.go",
	"peertrust_parity_test.go",
	"signature_middleware_parity_test.go",
	"discovery_cache_parity_test.go",
	"outbound_parity_test.go",
	"persistence_parity_test.go",
}

// T0SnapshotFixtureIDs names exported Q5 T0 snapshot fixtures in wiringtest.
var T0SnapshotFixtureIDs = []string{
	"SnapshotHarnessWireOptions",
	"SnapshotProductionWireOptions",
	"SnapshotCoreServicesOrder",
	"SnapshotAppServicesOrder",
	"SnapshotRootService",
	"SnapshotUnprotectedSets",
}

// WiringPackageRelPath is the T1 composition-root package directory.
const WiringPackageRelPath = "internal/wiring"

// WiringDir joins module root with the wiring package path.
func WiringDir(moduleRoot string) string {
	return filepath.Join(moduleRoot, WiringPackageRelPath)
}
