// Package directoryservice handles JWS fetch, verification, and Appendix C parsing
// for OCM directory service listings.
package directoryservice

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// EndpointConfig is a Directory Service endpoint configured in a trust group.
type EndpointConfig struct {
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// VerificationKey is a public key used to verify Directory Service JWS payloads.
type VerificationKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Algorithm    string `json:"algorithm"` // RS256, ES256, Ed25519
	Active       bool   `json:"active"`
}

// Listing is a verified Directory Service listing (strict Appendix C format).
type Listing struct {
	Federation string   `json:"federation"`
	Servers    []Server `json:"servers"`
}

// Server is a server entry in a Directory Service listing.
type Server struct {
	URL         string `json:"url"`
	DisplayName string `json:"displayName"`
}

// Client fetches and verifies Directory Service listings.
type Client struct {
	httpClient *httpclient.Client
}

// NewClient creates a new Directory Service client.
func NewClient(httpClient *httpclient.Client) *Client {
	return &Client{httpClient: httpClient}
}

// FetchListing fetches, verifies, and parses the Directory Service listing.
// Strict Appendix C format only: {federation: "...", servers: [{url, displayName}]}.
func (c *Client) FetchListing(ctx context.Context, directoryServiceURL string, keys []VerificationKey) (*Listing, error) {
	body, resp, err := c.httpClient.GetJSON(ctx, directoryServiceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch directory service: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	listing, err := c.parseAndVerifyJWS(body, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to verify directory service response: %w", err)
	}

	return listing, nil
}

// parseAndVerifyJWS parses JWS in any RFC 7515 serialization (compact, flattened
// JSON, general JSON) and verifies against the provided keys using go-jose.
func (c *Client) parseAndVerifyJWS(body []byte, keys []VerificationKey) (*Listing, error) {
	algorithms := collectAlgorithms(keys)
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("no active verification keys with recognized algorithms")
	}

	jws, err := jose.ParseSigned(string(body), algorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// Try each active key until one verifies.
	// go-jose Verify handles single-signature JWS (compact + flattened).
	// go-jose VerifyMulti handles general JSON with signatures[] array.
	multi := len(jws.Signatures) > 1

	for _, key := range keys {
		if !key.Active {
			continue
		}

		pubKey, err := parsePublicKey(key.PublicKeyPEM)
		if err != nil {
			continue
		}

		var payload []byte
		if multi {
			_, _, payload, err = jws.VerifyMulti(pubKey)
		} else {
			payload, err = jws.Verify(pubKey)
		}
		if err != nil {
			continue
		}

		return parseListing(payload)
	}

	return nil, fmt.Errorf("JWS signature verification failed (F2)")
}

// collectAlgorithms builds the allowed algorithm set from active keys.
func collectAlgorithms(keys []VerificationKey) []jose.SignatureAlgorithm {
	seen := make(map[jose.SignatureAlgorithm]bool)
	var result []jose.SignatureAlgorithm

	for _, key := range keys {
		if !key.Active {
			continue
		}

		alg, ok := mapAlgorithm(key.Algorithm)
		if !ok {
			continue
		}

		if !seen[alg] {
			seen[alg] = true
			result = append(result, alg)
		}
	}

	return result
}

// mapAlgorithm maps config algorithm strings to go-jose constants.
func mapAlgorithm(algorithm string) (jose.SignatureAlgorithm, bool) {
	switch algorithm {
	case "Ed25519", "ed25519", "EdDSA":
		return jose.EdDSA, true
	case "RS256":
		return jose.RS256, true
	case "ES256":
		return jose.ES256, true
	default:
		return "", false
	}
}

// parseListing parses the verified JWS payload as strict Appendix C format.
// Only accepts: {federation: "...", servers: [{url: "...", displayName: "..."}]}.
func parseListing(payload []byte) (*Listing, error) {
	var listing Listing
	if err := json.Unmarshal(payload, &listing); err != nil {
		return nil, fmt.Errorf("failed to parse directory service listing: %w", err)
	}

	if listing.Federation == "" {
		return nil, fmt.Errorf("directory service listing missing required 'federation' field")
	}

	return &listing, nil
}

func parsePublicKey(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}
