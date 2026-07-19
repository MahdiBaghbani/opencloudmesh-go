package discovery

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

const expectedAPIVersion = "1.4.0"

func validateDiscovery(disc *Discovery, discoveryOrigin string) error {
	if disc.APIVersion != expectedAPIVersion {
		return fmt.Errorf("apiVersion %q is not supported (want %q)", disc.APIVersion, expectedAPIVersion)
	}

	if disc.EndPoint == "" {
		return fmt.Errorf("endPoint is required")
	}
	if !isAbsoluteURL(disc.EndPoint) {
		return fmt.Errorf("endPoint must be absolute")
	}
	if !sameAuthority(disc.EndPoint, discoveryOrigin) {
		return fmt.Errorf("endPoint authority must match discovery origin")
	}

	hasExchangeToken := disc.HasCapability("exchange-token")
	if hasExchangeToken && disc.TokenEndPoint == "" {
		return fmt.Errorf("exchange-token capability requires tokenEndPoint")
	}
	if !hasExchangeToken && disc.TokenEndPoint != "" {
		return fmt.Errorf("tokenEndPoint requires exchange-token capability")
	}
	if disc.TokenEndPoint != "" {
		if !isAbsoluteURL(disc.TokenEndPoint) {
			return fmt.Errorf("tokenEndPoint must be absolute")
		}
		if !sameAuthority(disc.TokenEndPoint, discoveryOrigin) {
			return fmt.Errorf("tokenEndPoint authority must match discovery origin")
		}
	}

	if disc.InviteAcceptDialog != "" {
		if !isAbsoluteURL(disc.InviteAcceptDialog) {
			return fmt.Errorf("inviteAcceptDialog must be absolute after normalization")
		}
		if !sameAuthority(disc.InviteAcceptDialog, discoveryOrigin) {
			return fmt.Errorf("inviteAcceptDialog authority must match discovery origin")
		}
	}

	for i, rt := range disc.ResourceTypes {
		if err := validateResourceType(rt); err != nil {
			return fmt.Errorf("resourceTypes[%d]: %w", i, err)
		}
	}

	return nil
}

func validateResourceType(rt ResourceType) error {
	if rt.Name == "" {
		return fmt.Errorf("name is required")
	}
	for name, role := range rt.Protocols {
		if err := validateProtocolRole(name, role); err != nil {
			return fmt.Errorf("protocols[%q]: %w", name, err)
		}
	}
	return nil
}

func validateProtocolRole(name string, role spec.ProtocolRole) error {
	switch name {
	case "webdav", "talk":
		if _, ok := role.StringValue(); !ok {
			return fmt.Errorf("must be a string path")
		}
	case "webdav-receive":
		wr, ok := role.WebDAVReceive()
		if !ok {
			return fmt.Errorf("must be an object with uri")
		}
		switch wr.URI {
		case spec.WebDAVReceiveURIAbsolute, spec.WebDAVReceiveURIRelative:
		default:
			return fmt.Errorf("uri must be absolute or relative")
		}
	case "webapp-receive":
		if _, ok := role.WebAppReceive(); !ok {
			return fmt.Errorf("must be an object with targets")
		}
	case "webapp", "ssh-receive":
		if !role.IsEmptyObject() {
			return fmt.Errorf("must be an empty object")
		}
	default:
		if _, ok := role.StringValue(); ok {
			return nil
		}
		if role.IsEmptyObject() {
			return nil
		}
		if _, ok := role.WebDAVReceive(); ok {
			return nil
		}
		if _, ok := role.WebAppReceive(); ok {
			return nil
		}
		return fmt.Errorf("malformed protocol role")
	}
	return nil
}

func sameAuthority(absoluteURI, discoveryOrigin string) bool {
	devAllowHTTP := strings.HasPrefix(strings.ToLower(discoveryOrigin), "http://")
	resolver := peerorigin.NewResolver(devAllowHTTP)
	return resolver.IsAbsoluteURIAllowed(absoluteURI, discoveryOrigin)
}

func discoveryOriginFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimSuffix(rawURL, "/")
	}
	return u.Scheme + "://" + u.Host
}
