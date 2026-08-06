// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package localidentity is the single source of truth for this instance's
// published public identity: origin, provider domain, base path, and endpoint base.
package localidentity

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

// Identity holds the local public identity contract derived once at startup.
type Identity struct {
	// Origin is the normalized public origin (scheme + host + port).
	Origin string

	// Scheme is http or https from Origin.
	Scheme string

	// ProviderDomain is the published sender/provider domain with default ports
	// stripped (scheme-aware via hostport.Normalize).
	ProviderDomain string

	// ProviderDomainCompare is the same normalized provider authority used for
	// identity comparison today (default ports stripped).
	ProviderDomainCompare string

	// ExternalBasePath is the validated app base path: "" or leading slash with no trailing slash.
	ExternalBasePath string

	// EndpointBase is Origin + ExternalBasePath.
	EndpointBase string
}

// ValidateExternalBasePath validates external_base_path format.
// Returns the path unchanged when valid.
func ValidateExternalBasePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	if path != strings.TrimSpace(path) {
		return "", fmt.Errorf("localidentity: external_base_path must not contain leading or trailing whitespace")
	}

	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("localidentity: external_base_path %q must start with / when set", path)
	}

	if len(path) >= 2 && (path[1] == '/' || path[1] == '\\') {
		return "", fmt.Errorf("localidentity: external_base_path %q must not have '/' or '\\' in the second position", path)
	}

	if strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("localidentity: external_base_path %q must not have a trailing slash", path)
	}

	if strings.Contains(path, "..") {
		return "", fmt.Errorf("localidentity: external_base_path %q must not contain parent-directory path segments", path)
	}

	if strings.Contains(path, "//") {
		return "", fmt.Errorf("localidentity: external_base_path %q must not contain empty path segments", path)
	}

	if strings.Contains(path, "\\") {
		return "", fmt.Errorf("localidentity: external_base_path %q must not contain backslashes", path)
	}

	return path, nil
}

// Derive builds Identity from config public_origin and external_base_path.
func Derive(publicOrigin, externalBasePath string) (Identity, error) {
	validatedBasePath, err := ValidateExternalBasePath(externalBasePath)
	if err != nil {
		return Identity{}, err
	}

	if publicOrigin == "" {
		return Identity{}, fmt.Errorf("localidentity: public_origin is required")
	}

	origin, err := instanceid.NormalizePublicOrigin(publicOrigin)
	if err != nil {
		return Identity{}, fmt.Errorf("localidentity: derive origin: %w", err)
	}

	scheme := schemeFromOrigin(publicOrigin)
	if scheme == "" {
		scheme = "https"
	}

	rawHost, err := instanceid.ProviderFQDN(publicOrigin)
	if err != nil {
		return Identity{}, fmt.Errorf("localidentity: derive provider domain: %w", err)
	}

	normalizedProviderDomain, err := hostport.Normalize(rawHost, scheme)
	if err != nil {
		return Identity{}, fmt.Errorf("localidentity: normalize provider domain: %w", err)
	}

	return Identity{
		Origin:                origin,
		Scheme:                scheme,
		ProviderDomain:        normalizedProviderDomain,
		ProviderDomainCompare: normalizedProviderDomain,
		ExternalBasePath:      validatedBasePath,
		EndpointBase:          origin + validatedBasePath,
	}, nil
}

func schemeFromOrigin(publicOrigin string) string {
	if publicOrigin == "" {
		return ""
	}

	u, err := url.Parse(publicOrigin)
	if err != nil || u.Scheme == "" {
		return ""
	}

	return strings.ToLower(u.Scheme)
}
