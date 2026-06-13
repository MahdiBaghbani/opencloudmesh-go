// Package localidentity provides shared test fixtures for local public identity.
package localidentity

import (
	"testing"

	li "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// MustTestIdentity derives Identity from publicOrigin and externalBasePath or fatals the test.
func MustTestIdentity(t *testing.T, publicOrigin, externalBasePath string) li.Identity {
	t.Helper()
	id, err := li.Derive(publicOrigin, externalBasePath)
	if err != nil {
		t.Fatalf("localidentity.Derive(%q, %q): %v", publicOrigin, externalBasePath, err)
	}
	return id
}
