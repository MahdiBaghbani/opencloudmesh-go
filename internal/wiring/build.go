// Package wiring is the composition root for opencloudmesh-go process startup.
// T1 skeleton: exported option/result types only; wiring.Build lands in T2.
package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
)

// BuildOpts controls which optional infrastructure wiring builds.
// During the bootstrap cutover window this aliases app.WireOptions.
type BuildOpts = app.WireOptions

// BuildResult holds values callers need after wiring completes.
// During the bootstrap cutover window this aliases app.BootstrapResult.
type BuildResult = app.BootstrapResult
