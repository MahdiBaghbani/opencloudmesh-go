package incoming

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

func ExtractSenderHost(sender string) string {
	_, provider, err := address.Parse(sender)
	if err != nil {
		return ""
	}
	return strings.ToLower(provider)
}

func isCanonicalProtocolName(name string) bool {
	return name == "webdav" || name == "multi"
}
