// Package spec defines OCM spec-shaped types for discovery and token exchange.
// These are wire-format types matching the OCM-API specification.
// See: https://github.com/cs3org/OCM-API/blob/develop/spec.yaml
package spec

import (
	"fmt"
	"net/url"
	"path"
)

// Discovery represents the OCM discovery response.
type Discovery struct {
	Enabled       bool           `json:"enabled"`
	APIVersion    string         `json:"apiVersion"`
	EndPoint      string         `json:"endPoint"`
	Provider      string         `json:"provider,omitempty"`
	ResourceTypes []ResourceType `json:"resourceTypes"`
	Capabilities  []string       `json:"capabilities,omitempty"`
	Criteria      []string       `json:"criteria"` // Always present, serializes as [] when empty
	PublicKeys    []PublicKey    `json:"publicKeys,omitempty"`
	TokenEndPoint      string `json:"tokenEndPoint,omitempty"`      // Required when exchange-token capability is advertised
	InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"` // URL for the invite-accept dialog (WAYF)
}

// ResourceType describes a supported resource type.
type ResourceType struct {
	Name       string            `json:"name"`
	ShareTypes []string          `json:"shareTypes"`
	Protocols  map[string]string `json:"protocols"`
}

// PublicKey represents a public key for RFC 9421 HTTP signatures.
type PublicKey struct {
	KeyID        string `json:"keyId"`
	PublicKeyPem string `json:"publicKeyPem"`
	Algorithm    string `json:"algorithm,omitempty"`
}

// HasCapability returns true if the discovery document includes the given capability.
func (d *Discovery) HasCapability(cap string) bool {
	for _, c := range d.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// HasCriteria returns true if the discovery document includes the given criteria token.
func (d *Discovery) HasCriteria(criterion string) bool {
	for _, c := range d.Criteria {
		if c == criterion {
			return true
		}
	}
	return false
}

// GetEndpoint returns the OCM endpoint URL.
func (d *Discovery) GetEndpoint() string {
	return d.EndPoint
}

// GetWebDAVPath returns the WebDAV protocol path from the first file resource type.
func (d *Discovery) GetWebDAVPath() string {
	for _, rt := range d.ResourceTypes {
		if rt.Name == "file" {
			if p, ok := rt.Protocols["webdav"]; ok {
				return p
			}
		}
	}
	return ""
}

// GetPublicKey returns the public key with the given keyID, or nil if not found.
func (d *Discovery) GetPublicKey(keyID string) *PublicKey {
	for i := range d.PublicKeys {
		if d.PublicKeys[i].KeyID == keyID {
			return &d.PublicKeys[i]
		}
	}
	return nil
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
