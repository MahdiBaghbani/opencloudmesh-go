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
	"log/slog"
	"net/url"

	"github.com/go-jose/go-jose/v4"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// EndpointConfig is a Directory Service endpoint configured in a trust group.
type EndpointConfig struct {
	URL          string `json:"url"`
	Enabled      bool   `json:"enabled"`
	Verification string `json:"verification,omitempty"` // required, optional, off
}

// VerificationKey is a public key used to verify Directory Service JWS payloads.
type VerificationKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Algorithm    string `json:"algorithm"` // RS256, ES256, Ed25519
	Active       bool   `json:"active"`
}

// Listing is a Directory Service listing (strict Appendix C format).
// Verified is true when JWS verification succeeded, false for unverified payloads.
type Listing struct {
	Federation string   `json:"federation"`
	Servers    []Server `json:"servers"`
	Verified   bool     `json:"-"`
}

// Server is a server entry in a Directory Service listing.
type Server struct {
	URL         string `json:"url"`
	DisplayName string `json:"displayName"`
}

// Client fetches and verifies Directory Service listings.
type Client struct {
	httpClient                *httpclient.Client
	defaultVerificationPolicy string
	logger                    *slog.Logger
}

// NewClient creates a new Directory Service client.
// defaultVerificationPolicy sets the fallback when per-call policy is empty.
func NewClient(httpClient *httpclient.Client, defaultVerificationPolicy string, logger *slog.Logger) *Client {
	logger = logutil.NoopIfNil(logger)
	return &Client{
		httpClient:                httpClient,
		defaultVerificationPolicy: defaultVerificationPolicy,
		logger:                    logger,
	}
}

// FetchListing fetches, verifies, and parses the Directory Service listing.
// verificationPolicy overrides the client-level default when non-empty.
// Policies: "required" (verify or fail), "optional" (verify if possible, accept
// unsigned, reject bad signatures), "off" (accept without verification).
// Verified listings have invalid server URLs filtered per Appendix C constraints.
func (c *Client) FetchListing(ctx context.Context, directoryServiceURL string, keys []VerificationKey, verificationPolicy string) (*Listing, error) {
	body, resp, err := c.httpClient.GetJSON(ctx, directoryServiceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch directory service: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	policy := c.effectivePolicy(verificationPolicy)

	var listing *Listing
	switch policy {
	case "off":
		listing, err = c.parseUnverified(body)
	case "optional":
		listing, err = c.parseWithOptionalVerification(body, keys)
	default: // "required" and any unrecognized value
		listing, err = c.parseWithRequiredVerification(body, keys)
	}
	if err != nil {
		return nil, err
	}

	// URL validation applies only to verified listings.
	if listing.Verified {
		listing.Servers = c.filterValidServerURLs(listing.Servers)
	}

	return listing, nil
}

func (c *Client) effectivePolicy(override string) string {
	if override != "" {
		return override
	}
	if c.defaultVerificationPolicy != "" {
		return c.defaultVerificationPolicy
	}
	return "required"
}

func (c *Client) parseUnverified(body []byte) (*Listing, error) {
	listing, err := parseListing(body)
	if err != nil {
		return nil, err
	}
	listing.Verified = false
	return listing, nil
}

func (c *Client) parseWithRequiredVerification(body []byte, keys []VerificationKey) (*Listing, error) {
	listing, err := c.parseAndVerifyJWS(body, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to verify directory service response: %w", err)
	}
	listing.Verified = true
	return listing, nil
}

// parseWithOptionalVerification tries JWS verification, falling back to unsigned
// acceptance. JWS with bad signatures is always rejected (compromised data).
func (c *Client) parseWithOptionalVerification(body []byte, keys []VerificationKey) (*Listing, error) {
	algorithms := collectAlgorithms(keys)
	if len(algorithms) == 0 {
		return c.parseUnverified(body)
	}

	jws, err := jose.ParseSigned(string(body), algorithms)
	if err != nil {
		// Not valid JWS: accept as unsigned.
		return c.parseUnverified(body)
	}

	// Body IS JWS -- signature must verify. Bad signatures are never accepted.
	listing, err := c.verifyJWS(jws, keys)
	if err != nil {
		return nil, fmt.Errorf("directory service response has JWS wrapper but verification failed: %w", err)
	}
	listing.Verified = true
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

	return c.verifyJWS(jws, keys)
}

// verifyJWS attempts to verify a parsed JWS against the provided keys.
func (c *Client) verifyJWS(jws *jose.JSONWebSignature, keys []VerificationKey) (*Listing, error) {
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

// filterValidServerURLs drops entries with invalid URLs from verified listings.
// Appendix C constraints: absolute URL with http(s) scheme+host, optional port,
// path must be empty or "/", no userinfo/query/fragment.
func (c *Client) filterValidServerURLs(servers []Server) []Server {
	valid := make([]Server, 0, len(servers))
	for _, s := range servers {
		if isValidServerURL(s.URL) {
			valid = append(valid, s)
		} else {
			c.logger.Warn("dropping server with invalid URL from verified listing",
				"url", s.URL, "display_name", s.DisplayName)
		}
	}
	return valid
}

// isValidServerURL checks Appendix C URL constraints for a server entry.
func isValidServerURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if !u.IsAbs() || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	return true
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

// parseListing parses the payload as strict Appendix C format.
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
