package incoming

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

// ExtractSenderHost extracts the host (provider) from an OCM address using last-@ semantics.
// The identifier part may contain '@' (e.g. email addresses).
func ExtractSenderHost(sender string) string {
	_, provider, err := address.Parse(sender)
	if err != nil {
		return ""
	}
	return strings.ToLower(provider)
}

// IsAbsoluteURI checks if a URI is absolute (contains ://).
func IsAbsoluteURI(uri string) bool {
	return strings.Contains(uri, "://")
}
