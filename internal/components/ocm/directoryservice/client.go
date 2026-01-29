// Package directoryservice handles JWS fetch, verification, and Appendix C parsing
// for OCM directory service listings.
package directoryservice

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

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

// appendixCPayload represents the Appendix C JWS envelope format.
type appendixCPayload struct {
	Payload    string `json:"payload"`
	Protected  string `json:"protected"`
	Signature  string `json:"signature"`
	Signatures []struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	} `json:"signatures,omitempty"`
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

func (c *Client) parseAndVerifyJWS(body []byte, keys []VerificationKey) (*Listing, error) {
	// Try Appendix C JSON format first
	var payload appendixCPayload
	if err := json.Unmarshal(body, &payload); err == nil && payload.Payload != "" {
		return c.verifyAppendixC(payload, keys)
	}

	// Try compact JWS format
	compactJWS := strings.TrimSpace(string(body))
	parts := strings.Split(compactJWS, ".")
	if len(parts) == 3 {
		return c.verifyCompactJWS(parts, keys)
	}

	return nil, fmt.Errorf("unrecognized directory service response format")
}

func (c *Client) verifyAppendixC(payload appendixCPayload, keys []VerificationKey) (*Listing, error) {
	signingInput := payload.Protected + "." + payload.Payload

	sig, err := base64URLDecode(payload.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	verified := false
	for _, key := range keys {
		if !key.Active {
			continue
		}

		pubKey, err := parsePublicKey(key.PublicKeyPEM)
		if err != nil {
			continue
		}

		if verifySignature(pubKey, key.Algorithm, []byte(signingInput), sig) {
			verified = true
			break
		}
	}

	if !verified {
		return nil, fmt.Errorf("JWS signature verification failed (F2)")
	}

	payloadBytes, err := base64URLDecode(payload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	return parseListing(payloadBytes)
}

func (c *Client) verifyCompactJWS(parts []string, keys []VerificationKey) (*Listing, error) {
	header, payload, sig := parts[0], parts[1], parts[2]

	signingInput := header + "." + payload

	sigBytes, err := base64URLDecode(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	verified := false
	for _, key := range keys {
		if !key.Active {
			continue
		}

		pubKey, err := parsePublicKey(key.PublicKeyPEM)
		if err != nil {
			continue
		}

		if verifySignature(pubKey, key.Algorithm, []byte(signingInput), sigBytes) {
			verified = true
			break
		}
	}

	if !verified {
		return nil, fmt.Errorf("JWS signature verification failed (F2)")
	}

	payloadBytes, err := base64URLDecode(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	return parseListing(payloadBytes)
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

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
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

func verifySignature(pubKey crypto.PublicKey, algorithm string, message, signature []byte) bool {
	switch algorithm {
	case "Ed25519", "ed25519":
		if edKey, ok := pubKey.(ed25519.PublicKey); ok {
			return ed25519.Verify(edKey, message, signature)
		}
	case "RS256":
		if rsaKey, ok := pubKey.(*rsa.PublicKey); ok {
			h := crypto.SHA256.New()
			h.Write(message)
			return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h.Sum(nil), signature) == nil
		}
	case "ES256":
		if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			h := crypto.SHA256.New()
			h.Write(message)
			return ecdsa.VerifyASN1(ecKey, h.Sum(nil), signature)
		}
	}
	return false
}
