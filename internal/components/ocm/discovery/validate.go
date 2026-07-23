package discovery

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func validateDiscovery(disc *spec.Discovery, discoveryOrigin string, policy *VersionPolicy) error {
	if policy == nil {
		policy = NewVersionPolicy()
	}

	var warnings []string

	ok, warn := policy.Accept(disc.APIVersion)
	if !ok {
		return fmt.Errorf(
			"apiVersion %q is not supported (policy %d, pin %q)",
			disc.APIVersion, policy.Mode, spec.APIVersionPin,
		)
	}
	if warn != "" {
		warnings = append(warnings, warn)
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

	hasExchangeToken := disc.HasCapability(spec.CapabilityExchangeToken)
	if hasExchangeToken && disc.TokenEndPoint == "" {
		return fmt.Errorf("%s capability requires tokenEndPoint", spec.CapabilityExchangeToken)
	}
	if !hasExchangeToken && disc.TokenEndPoint != "" {
		return fmt.Errorf("tokenEndPoint requires %s capability", spec.CapabilityExchangeToken)
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
		if err := validateResourceType(rt, &warnings); err != nil {
			return fmt.Errorf("resourceTypes[%d]: %w", i, err)
		}
	}

	if len(warnings) > 0 {
		disc.Warnings = append(disc.Warnings, warnings...)
	}

	return nil
}

func validateResourceType(rt spec.ResourceType, warnings *[]string) error {
	if rt.Name == "" {
		return fmt.Errorf("name is required")
	}
	for name, role := range rt.Protocols {
		w, err := validateProtocolRole(name, role)
		if err != nil {
			return fmt.Errorf("protocols[%q]: %w", name, err)
		}
		if w != "" {
			*warnings = append(*warnings, w)
		}
	}
	return nil
}

func validateProtocolRole(name string, role spec.ProtocolRole) (warning string, err error) {
	switch name {
	case "webdav":
		if _, ok := role.StringValue(); !ok {
			return "", fmt.Errorf("must be a string path")
		}
	case "webdav-receive":
		wr, ok := role.WebDAVReceive()
		if !ok {
			return "", fmt.Errorf("must be an object with uri")
		}
		switch wr.URI {
		case spec.WebDAVReceiveURIAbsolute, spec.WebDAVReceiveURIRelative:
		default:
			return "", fmt.Errorf("uri must be absolute or relative")
		}
	default:
		return fmt.Sprintf("protocol role %q preserved but not locally shape-validated", name), nil
	}
	return "", nil
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
