package ui

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Inputs holds dependencies for the UI service constructor.
type Inputs struct {
	LocalIdentity localidentity.Identity
}
