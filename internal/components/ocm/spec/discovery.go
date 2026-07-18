// Package spec defines OCM wire-format types (discovery, shares, invites, errors).
// See https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1#ocm-api-discovery
package spec

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Canonical OCM-API discovery criteria strings (IETF-RFC / OpenAPI).
const (
	CriteriaMustUseHTTPSig    = "must-use-http-sig"
	CriteriaMustExchangeToken = "must-exchange-token"
)

type Discovery struct {
	Enabled            bool           `json:"enabled"`
	APIVersion         string         `json:"apiVersion"`
	EndPoint           string         `json:"endPoint"`
	Provider           string         `json:"provider,omitempty"`
	ResourceTypes      []ResourceType `json:"resourceTypes"`
	Capabilities       []string       `json:"capabilities,omitempty"`
	Criteria           []string       `json:"criteria"`                     // Always present, serializes as [] when empty
	TokenEndPoint      string         `json:"tokenEndPoint,omitempty"`      // Required when exchange-token capability is advertised
	InviteAcceptDialog string         `json:"inviteAcceptDialog,omitempty"` // URL for the invite-accept dialog (WAYF)
}

type ResourceType struct {
	Name       string    `json:"name"`
	ShareTypes []string  `json:"shareTypes"`
	Protocols  Protocols `json:"protocols"`
}

func (d *Discovery) HasCapability(cap string) bool {
	for _, c := range d.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

func (d *Discovery) HasCriteria(criterion string) bool {
	for _, c := range d.Criteria {
		if c == criterion {
			return true
		}
	}
	return false
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
	return d.HasCapability("http-sig")
}

// DiscoveryPaths holds route-derived discovery path fields before policy overlays.
type DiscoveryPaths struct {
	EndPoint           string
	TokenEndPoint      string
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
		for _, f := range row.DiscoveryFields {
			if f == field {
				return absolutePathFromHostRoot(origin, row.FullPath)
			}
		}
	}
	return ""
}

// DeriveDiscoveryPathsFromEndpointBase projects EndPoint and TokenEndPoint from an
// explicit configured endpoint base (public origin plus external base path). The
// endpoint base already encodes external_base_path, so token paths join the OCM
// protocol mount and configured token segment rather than re-deriving host-root
// route inventory paths.
func DeriveDiscoveryPathsFromEndpointBase(endpointBase, ocmPrefix string, opts service.RouteOpts) DiscoveryPaths {
	paths := DiscoveryPaths{}
	if endpointBase == "" {
		return paths
	}

	paths.EndPoint, _ = url.JoinPath(endpointBase, ocmPrefix)

	tokenSegment := tokenDiscoverySegment(opts)
	paths.TokenEndPoint, _ = url.JoinPath(endpointBase, ocmPrefix, tokenSegment)
	return paths
}

func tokenDiscoverySegment(opts service.RouteOpts) string {
	for _, row := range service.DerivedRouteInventory(opts) {
		for _, field := range row.DiscoveryFields {
			if field == "tokenEndPoint" {
				return strings.TrimPrefix(row.Pattern, "/")
			}
		}
	}
	tokenPath := opts.TokenExchangePath
	if tokenPath == "" {
		tokenPath = "token"
	}
	return tokenPath
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
	return d.HasCapability("exchange-token") && d.TokenEndPoint != ""
}

func (d *Discovery) GetEndpoint() string {
	return d.EndPoint
}

func (d *Discovery) GetWebDAVPath() string {
	for _, rt := range d.ResourceTypes {
		if rt.Name == "file" {
			if p, ok := rt.Protocols.StringRole("webdav"); ok {
				return p
			}
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
