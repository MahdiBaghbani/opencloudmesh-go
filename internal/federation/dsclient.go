package federation

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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
)

// DirectoryServiceClient fetches and verifies DS membership.
type DirectoryServiceClient struct {
	httpClient *httpclient.Client
}

// NewDirectoryServiceClient creates a new DS client.
func NewDirectoryServiceClient(httpClient *httpclient.Client) *DirectoryServiceClient {
	return &DirectoryServiceClient{httpClient: httpClient}
}

// AppendixCPayload represents the Appendix C JWS payload format.
type AppendixCPayload struct {
	Payload    string `json:"payload"`
	Protected  string `json:"protected"`
	Signature  string `json:"signature"`
	Signatures []struct {
		Protected string `json:"protected"`
		Signature string `json:"signature"`
	} `json:"signatures,omitempty"`
}

// DSMemberEntry represents an entry in the DS membership list.
type DSMemberEntry struct {
	Domain string `json:"domain"`
	Name   string `json:"name,omitempty"`
}

// FetchMembership fetches and verifies membership from a DS URL.
func (c *DirectoryServiceClient) FetchMembership(ctx context.Context, dsURL string, keys []FederationKey) ([]Member, error) {
	// Fetch the DS response
	body, resp, err := c.httpClient.GetJSON(ctx, dsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DS: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DS returned status %d", resp.StatusCode)
	}

	// Try to parse as Appendix C JWS format
	members, err := c.parseAndVerifyJWS(body, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to verify DS response: %w", err)
	}

	return members, nil
}

// parseAndVerifyJWS parses and verifies the JWS response.
func (c *DirectoryServiceClient) parseAndVerifyJWS(body []byte, keys []FederationKey) ([]Member, error) {
	// Try Appendix C JSON format first
	var payload AppendixCPayload
	if err := json.Unmarshal(body, &payload); err == nil && payload.Payload != "" {
		return c.verifyAppendixC(payload, keys)
	}

	// Try compact JWS format
	compactJWS := strings.TrimSpace(string(body))
	parts := strings.Split(compactJWS, ".")
	if len(parts) == 3 {
		return c.verifyCompactJWS(parts, keys)
	}

	return nil, fmt.Errorf("unrecognized DS response format")
}

// verifyAppendixC verifies an Appendix C format JWS.
func (c *DirectoryServiceClient) verifyAppendixC(payload AppendixCPayload, keys []FederationKey) ([]Member, error) {
	// Build signing input
	signingInput := payload.Protected + "." + payload.Payload

	// Decode signature
	sig, err := base64URLDecode(payload.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Try each active key
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

	// Decode payload
	payloadBytes, err := base64URLDecode(payload.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	return parseMemberList(payloadBytes)
}

// verifyCompactJWS verifies a compact JWS format.
func (c *DirectoryServiceClient) verifyCompactJWS(parts []string, keys []FederationKey) ([]Member, error) {
	header, payload, sig := parts[0], parts[1], parts[2]

	// Build signing input
	signingInput := header + "." + payload

	// Decode signature
	sigBytes, err := base64URLDecode(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Try each active key
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

	// Decode payload
	payloadBytes, err := base64URLDecode(payload)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	return parseMemberList(payloadBytes)
}

// parseMemberList parses the member list from JSON payload.
func parseMemberList(payload []byte) ([]Member, error) {
	// Try array format
	var entries []DSMemberEntry
	if err := json.Unmarshal(payload, &entries); err == nil {
		var members []Member
		for _, e := range entries {
			members = append(members, Member{
				Host: e.Domain,
				Name: e.Name,
			})
		}
		return members, nil
	}

	// Try object with servers array
	var obj struct {
		Servers []DSMemberEntry `json:"servers"`
	}
	if err := json.Unmarshal(payload, &obj); err == nil && len(obj.Servers) > 0 {
		var members []Member
		for _, e := range obj.Servers {
			members = append(members, Member{
				Host: e.Domain,
				Name: e.Name,
			})
		}
		return members, nil
	}

	return nil, fmt.Errorf("unrecognized member list format")
}

// base64URLDecode decodes base64url-encoded data.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}

// parsePublicKey parses a PEM-encoded public key.
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

// verifySignature verifies a signature with the given algorithm.
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
