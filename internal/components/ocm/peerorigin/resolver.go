// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package peerorigin resolves peer origin (scheme and base URL) and validates
// absolute-URI peer authorities for OCM outbound and inbound peer-boundary
// callers. The strict default always resolves HTTPS; the only HTTP gate is
// an explicit dev-mode transport flag passed to NewResolver.
package peerorigin

import (
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Decision is the typed peer-origin and host-validation decision.
type Decision struct {
	PeerDomain string
	Scheme     string
	BaseURL    string
	AllowHTTP  bool
}

// Resolver resolves peer origin and validates absolute-URI peer authorities.
// A nil *Resolver resolves like a Resolver built with devAllowHTTP=false: it
// always resolves the canonical strict/HTTPS scheme and never preserves an
// explicit http:// input scheme.
type Resolver struct {
	devAllowHTTP bool
}

// NewResolver builds a Resolver. devAllowHTTP is the explicit dev-mode
// transport flag: when true, Resolve and IsAbsoluteURIAllowed allow the http
// scheme for every peer; when false, they always resolve/require https.
func NewResolver(devAllowHTTP bool) *Resolver {
	return &Resolver{devAllowHTTP: devAllowHTTP}
}

// Resolve resolves peer origin and scheme for peer-boundary callers. An
// empty or unparsable peerInput resolves to a zero Decision.
func (r *Resolver) Resolve(peerInput string) Decision {
	peerDomain, inputScheme := peerDomainFromInput(peerInput)
	if peerDomain == "" {
		return Decision{}
	}

	allowHTTP := r != nil && r.devAllowHTTP

	scheme := "https"
	if allowHTTP {
		scheme = "http"
	}

	switch inputScheme {
	case "https":
		scheme = "https"
	case "http":
		if allowHTTP {
			scheme = "http"
		}
	}

	return Decision{
		PeerDomain: peerDomain,
		Scheme:     scheme,
		BaseURL:    scheme + "://" + peerDomain,
		AllowHTTP:  allowHTTP,
	}
}

// IsAbsoluteURIAllowed validates an absolute URI against the resolved peer
// authority and transport policy. It never allows an http:// absoluteURI
// unless the resolver's dev-mode transport flag is enabled, and it only
// matches on the resolved peer authority or fails closed.
func (r *Resolver) IsAbsoluteURIAllowed(absoluteURI, peerInput string) bool {
	parsed, err := url.Parse(absoluteURI)
	if err != nil || parsed.Host == "" {
		return false
	}

	uriScheme := strings.ToLower(parsed.Scheme)
	if uriScheme != "http" && uriScheme != "https" {
		return false
	}

	origin := r.Resolve(peerInput)
	if origin.PeerDomain == "" {
		return false
	}

	if uriScheme == "http" && !origin.AllowHTTP {
		return false
	}

	return authorityMatch(parsed.Host, origin.PeerDomain, uriScheme)
}

func peerDomainFromInput(peerInput string) (string, string) {
	input := strings.TrimSpace(peerInput)
	if input == "" {
		return "", ""
	}

	if strings.Contains(input, "://") {
		parsed, err := url.Parse(input)
		if err == nil && parsed.Host != "" {
			return parsed.Host, strings.ToLower(parsed.Scheme)
		}
	}

	return input, ""
}

func authorityMatch(leftAuthority, rightAuthority, scheme string) bool {
	left, err := hostport.Normalize(leftAuthority, scheme)
	if err != nil {
		return false
	}

	right, err := hostport.Normalize(rightAuthority, scheme)
	if err != nil {
		return false
	}

	return left == right
}
