// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package spec defines OCM wire-format types (discovery, shares, invites, errors).
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1#ocm-api-discovery
package spec

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// APIVersionPin is the Layer 1 wire pin for OCM discovery apiVersion.
const APIVersionPin = "1.4.0"

// Discovery holds the OCM discovery document served by GET /ocm/.
type Discovery struct {
	Enabled            bool           `json:"enabled"`
	APIVersion         string         `json:"apiVersion"`
	EndPoint           string         `json:"endPoint"`
	Provider           string         `json:"provider,omitempty"`
	ResourceTypes      []ResourceType `json:"resourceTypes"`
	Capabilities       []string       `json:"capabilities,omitempty"`
	Criteria           []string       `json:"criteria"`                     // Always present, serializes as [] when empty
	TokenEndPoint      string         `json:"tokenEndPoint,omitempty"`      // Required when exchange-token capability is advertised
	JwksUri            string         `json:"jwksUri,omitempty"`            //nolint:revive // wire field name matches OCM spec jwksUri
	InviteAcceptDialog string         `json:"inviteAcceptDialog,omitempty"` // URL for the invite-accept dialog (WAYF)
	Warnings           []string       `json:"-"`
}

// ResourceType describes one entry in the discovery resourceTypes list.
type ResourceType struct {
	Name       string    `json:"name"`
	ShareTypes []string  `json:"shareTypes"`
	Protocols  Protocols `json:"protocols"`
}

// HasCapability reports whether the discovery advertises the given capability.
func (d *Discovery) HasCapability(capability string) bool {
	return slices.Contains(d.Capabilities, capability)
}

// HasCriteria reports whether the discovery lists the given criterion.
func (d *Discovery) HasCriteria(criterion string) bool {
	return slices.Contains(d.Criteria, criterion)
}

// RequiresHTTPSig reports whether the peer requires signed OCM requests per the
// IETF must-use-http-sig criterion.
func (d *Discovery) RequiresHTTPSig() bool {
	if d == nil {
		return false
	}

	return d.HasCriteria(CriteriaMustUseHTTPSig)
}

// IsHTTPSigCapable reports whether the peer advertises the http-sig capability.
func (d *Discovery) IsHTTPSigCapable() bool {
	if d == nil {
		return false
	}

	return d.HasCapability(CapabilityHTTPSig)
}

// DiscoveryPaths holds route-derived discovery path fields before policy overlays.
type DiscoveryPaths struct {
	EndPoint           string
	TokenEndPoint      string
	JwksURI            string
	WebDAVRoot         string
	InviteAcceptDialog string
}

// DeriveDiscoveryPaths projects discovery path fields from local identity and Routes(opts).
// ok is true when Origin is set and the OCM protocol endPoint could be projected.
func DeriveDiscoveryPaths(id localidentity.Identity, opts service.RouteOpts) (DiscoveryPaths, bool) {
	paths := DiscoveryPaths{}

	rows := service.Routes(opts)
	inv := service.DerivedRouteInventory(opts)

	if id.Origin != "" {
		for _, row := range rows {
			if row.ID == service.SubtreeDefaultID("ocm") {
				paths.EndPoint = absolutePathFromHostRoot(id.Origin, row.FullPath)
				break
			}
		}

		paths.TokenEndPoint = discoveryPathFromField(inv, "tokenEndPoint", id.Origin)
		paths.JwksURI = discoveryPathFromField(inv, "jwks", id.Origin)
	}

	if row, ok := rowByID(inv, service.RouteIDWebDAVOCMWildcard); ok {
		paths.WebDAVRoot = webdavRootFromWildcard(row.FullPath)
	}

	if row, ok := rowByID(inv, service.RouteIDUIAcceptInvite); ok && id.Origin != "" {
		paths.InviteAcceptDialog = absolutePathFromHostRoot(id.Origin, row.FullPath)
	}

	return paths, id.Origin != "" && paths.EndPoint != ""
}

func discoveryPathFromField(rows []service.RouteRow, field, origin string) string {
	for _, row := range rows {
		if slices.Contains(row.DiscoveryFields, field) {
			return absolutePathFromHostRoot(origin, row.FullPath)
		}
	}

	return ""
}

func rowByID(rows []service.RouteRow, id string) (service.RouteRow, bool) {
	for _, row := range rows {
		if row.ID == id {
			return row, true
		}
	}

	return service.RouteRow{}, false
}

func absolutePathFromHostRoot(origin, hostRootPath string) string {
	trimmed := strings.TrimPrefix(hostRootPath, "/")
	if trimmed == "" {
		return origin
	}

	joined, err := url.JoinPath(origin, trimmed)
	if err != nil {
		return origin + hostRootPath
	}

	return joined
}

func webdavRootFromWildcard(fullPath string) string {
	root := strings.TrimSuffix(fullPath, "/*")
	if root == "" {
		return "/"
	}

	if !strings.HasSuffix(root, "/") {
		root += "/"
	}

	return root
}

// ResolveInviteAcceptDialog resolves a relative inviteAcceptDialog against baseURL.
func ResolveInviteAcceptDialog(baseURL, dialog string) string {
	if dialog == "" {
		return ""
	}

	if strings.HasPrefix(dialog, "http://") || strings.HasPrefix(dialog, "https://") {
		return dialog
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return dialog
	}

	ref, err := url.Parse(dialog)
	if err != nil {
		return dialog
	}

	return base.ResolveReference(ref).String()
}

// SupportsTokenExchange reports whether the peer advertises a complete
// token-exchange capability set (capability + token endpoint).
func (d *Discovery) SupportsTokenExchange() bool {
	return d.HasCapability(CapabilityExchangeToken) && d.TokenEndPoint != ""
}

func (d *Discovery) GetEndpoint() string { //nolint:revive // exported: trivial getter for the endPoint field
	return d.EndPoint
}

// GetWebDAVPath returns the WebDAV protocol path for the "file" resource type, or empty if absent.
func (d *Discovery) GetWebDAVPath() string {
	for _, rt := range d.ResourceTypes {
		if rt.Name == "file" {
			if p, ok := rt.Protocols.StringRole(ProtocolWebDAV); ok {
				return p
			}
		}
	}

	return ""
}

// WebDAVReceiveURIKind reports the remote webdav-receive uri kind when advertised.
func (d *Discovery) WebDAVReceiveURIKind() WebDAVReceiveURIKind {
	if d == nil {
		return ""
	}

	for _, rt := range d.ResourceTypes {
		if wr, ok := rt.Protocols.WebDAVReceive(); ok {
			return wr.URI
		}
	}

	return ""
}

// BuildWebDAVURL constructs the full WebDAV URL for accessing a share.
func (d *Discovery) BuildWebDAVURL(shareID string) (string, error) {
	webdavPath := d.GetWebDAVPath()
	if webdavPath == "" {
		return "", fmt.Errorf("no WebDAV path in discovery")
	}

	endpointURL, err := url.Parse(d.EndPoint)
	if err != nil {
		return "", err
	}

	// Combine the endpoint host with the webdav path and share ID
	fullPath := path.Join(webdavPath, shareID)
	result := endpointURL.Scheme + "://" + endpointURL.Host + fullPath

	return result, nil
}
