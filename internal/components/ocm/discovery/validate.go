// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

	if err := validateDiscoveryEndpoint(disc, discoveryOrigin); err != nil {
		return err
	}

	if err := validateDiscoveryTokenEndpoint(disc, discoveryOrigin); err != nil {
		return err
	}

	if err := validateDiscoveryInviteDialog(disc, discoveryOrigin); err != nil {
		return err
	}

	if err := validateDiscoveryJwksUri(disc, discoveryOrigin); err != nil {
		return err
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

func validateDiscoveryEndpoint(disc *spec.Discovery, discoveryOrigin string) error {
	if disc.EndPoint == "" {
		return fmt.Errorf("endPoint is required")
	}

	if !isAbsoluteURL(disc.EndPoint) {
		return fmt.Errorf("endPoint must be absolute")
	}

	if !sameAuthority(disc.EndPoint, discoveryOrigin) {
		return fmt.Errorf("endPoint authority must match discovery origin")
	}

	return nil
}

func validateDiscoveryTokenEndpoint(disc *spec.Discovery, discoveryOrigin string) error {
	hasExchangeToken := disc.HasCapability(spec.CapabilityExchangeToken)
	if hasExchangeToken && disc.TokenEndPoint == "" {
		return fmt.Errorf("%s capability requires tokenEndPoint", spec.CapabilityExchangeToken)
	}

	if !hasExchangeToken && disc.TokenEndPoint != "" {
		return fmt.Errorf("tokenEndPoint requires %s capability", spec.CapabilityExchangeToken)
	}

	if disc.TokenEndPoint == "" {
		return nil
	}

	if !isAbsoluteURL(disc.TokenEndPoint) {
		return fmt.Errorf("tokenEndPoint must be absolute")
	}

	if !sameAuthority(disc.TokenEndPoint, discoveryOrigin) {
		return fmt.Errorf("tokenEndPoint authority must match discovery origin")
	}

	return nil
}

func validateDiscoveryInviteDialog(disc *spec.Discovery, discoveryOrigin string) error {
	if disc.InviteAcceptDialog == "" {
		return nil
	}

	if !isAbsoluteURL(disc.InviteAcceptDialog) {
		return fmt.Errorf("inviteAcceptDialog must be absolute after normalization")
	}

	if !sameAuthority(disc.InviteAcceptDialog, discoveryOrigin) {
		return fmt.Errorf("inviteAcceptDialog authority must match discovery origin")
	}

	return nil
}

// validateDiscoveryJwksUri validates a peer's advertised jwksUri. The field is
// authoritative, not a fixed path, so custom paths are accepted when they
// satisfy the transport and authority policy. An absent jwksUri is not an
// error here: the http-sig decision-to-discard rules apply at request
// verification time, not at discovery time.
//
// The same-authority rule keeps the JWKS target on the already-vetted
// discovery origin, so loopback, private, and link-local SSRF screening,
// cross-authority redirect blocking, and HTTPS-to-HTTP downgrade blocking stay
// with the shared safe HTTP client at fetch time; they are not duplicated here.
func validateDiscoveryJwksUri(disc *spec.Discovery, discoveryOrigin string) error { //nolint:revive // name matches the OCM spec jwksUri wire field
	if disc.JwksUri == "" {
		return nil
	}

	u, err := url.Parse(disc.JwksUri)
	if err != nil {
		return fmt.Errorf("jwksUri is malformed")
	}

	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("jwksUri must be absolute")
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("jwksUri scheme %q is not allowed", u.Scheme)
	}

	devAllowHTTP := strings.HasPrefix(strings.ToLower(discoveryOrigin), "http://")
	if scheme == "http" && !devAllowHTTP {
		return fmt.Errorf("jwksUri must use https outside development HTTP opt-in")
	}

	if u.User != nil {
		return fmt.Errorf("jwksUri must not contain credentials")
	}

	// Bare "#" leaves Fragment empty after url.Parse; reject any fragment delimiter.
	if strings.Contains(disc.JwksUri, "#") {
		return fmt.Errorf("jwksUri must not contain a fragment")
	}

	if !sameAuthority(disc.JwksUri, discoveryOrigin) {
		return fmt.Errorf("jwksUri authority must match discovery origin")
	}

	return nil
}

// ValidateLocalJwksURIOverride validates a configured local jwksUri override
// (signature.jwks_uri) against the resolved discovery endpoint authority. It
// reuses validateDiscoveryJwksUri, the same transport, credential, fragment,
// and same-authority policy enforced for peer-advertised jwksUri, so the
// local and peer paths never diverge. An empty override is not an error (it is
// a no-op); wiring calls this unconditionally at startup, including for an
// empty override. Callers should treat a non-nil error as a fail-fast startup
// error.
func ValidateLocalJwksURIOverride(jwksURI, discoveryOrigin string) error {
	return validateDiscoveryJwksUri(&spec.Discovery{JwksUri: jwksURI}, discoveryOrigin)
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
	case spec.ProtocolWebDAV:
		if _, ok := role.StringValue(); !ok {
			return "", fmt.Errorf("must be a string path")
		}
	case spec.ProtocolWebDAVReceive:
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
