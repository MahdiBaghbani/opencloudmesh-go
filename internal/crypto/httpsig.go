package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RFC9421Signer signs HTTP requests per RFC 9421.
type RFC9421Signer struct {
	keyManager *KeyManager
}

// NewRFC9421Signer creates a new signer.
func NewRFC9421Signer(km *KeyManager) *RFC9421Signer {
	return &RFC9421Signer{keyManager: km}
}

// DefaultCoveredComponents returns the default components to sign.
func DefaultCoveredComponents() []string {
	return []string{
		"@method",
		"@target-uri",
		"@authority",
		"content-type",
		"content-digest",
		"content-length",
	}
}

// SignRequest signs an HTTP request per RFC 9421.
// It adds Signature and Signature-Input headers.
func (s *RFC9421Signer) SignRequest(req *http.Request, body []byte) error {
	key := s.keyManager.GetSigningKey()
	if key == nil {
		return fmt.Errorf("no signing key available")
	}

	// Add Content-Digest if body is present
	if len(body) > 0 {
		digest := computeSHA256Digest(body)
		req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:", digest))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	// Get timestamp
	now := time.Now().Unix()

	// Build covered components
	components := DefaultCoveredComponents()

	// Filter to only include headers that exist
	var actualComponents []string
	for _, comp := range components {
		if strings.HasPrefix(comp, "@") {
			actualComponents = append(actualComponents, comp)
		} else if req.Header.Get(comp) != "" {
			actualComponents = append(actualComponents, comp)
		}
	}

	// Build signature base
	sigBase, err := buildSignatureBase(req, actualComponents)
	if err != nil {
		return fmt.Errorf("failed to build signature base: %w", err)
	}

	// Build @signature-params
	sigParams := buildSignatureParams(actualComponents, key.KeyID, now)

	// Complete signature base with @signature-params
	fullBase := sigBase + fmt.Sprintf("\"@signature-params\": %s", sigParams)

	// Sign
	sig, err := s.keyManager.Sign([]byte(fullBase))
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	// Base64 encode signature
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Set headers
	req.Header.Set("Signature-Input", fmt.Sprintf("sig1=%s", sigParams))
	req.Header.Set("Signature", fmt.Sprintf("sig1=:%s:", sigB64))

	return nil
}

// buildSignatureBase builds the signature base string per RFC 9421.
func buildSignatureBase(req *http.Request, components []string) (string, error) {
	var lines []string

	for _, comp := range components {
		var value string
		var err error

		switch comp {
		case "@method":
			value = req.Method
		case "@target-uri":
			value = req.URL.String()
		case "@authority":
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		case "@path":
			value = req.URL.Path
		case "@query":
			value = "?" + req.URL.RawQuery
		default:
			// Regular header
			value = req.Header.Get(comp)
			if value == "" {
				continue // Skip missing headers
			}
		}

		if err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("\"%s\": %s", strings.ToLower(comp), value))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// buildSignatureParams builds the @signature-params string.
func buildSignatureParams(components []string, keyID string, created int64) string {
	// Quote each component
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = fmt.Sprintf("\"%s\"", strings.ToLower(c))
	}

	// Build params
	params := fmt.Sprintf("(%s);created=%d;keyid=\"%s\";alg=\"ed25519\"",
		strings.Join(quoted, " "),
		created,
		keyID)

	return params
}

// RFC9421Verifier verifies HTTP request signatures per RFC 9421.
type RFC9421Verifier struct{}

// NewRFC9421Verifier creates a new verifier.
func NewRFC9421Verifier() *RFC9421Verifier {
	return &RFC9421Verifier{}
}

// VerificationResult contains the result of signature verification.
type VerificationResult struct {
	Verified bool
	KeyID    string
	Error    error
}

// VerifyRequest verifies an HTTP request signature.
// publicKeyFetcher is called to get the public key for a given keyId.
func (v *RFC9421Verifier) VerifyRequest(req *http.Request, body []byte,
	publicKeyFetcher func(keyID string) (ed25519.PublicKey, error)) *VerificationResult {

	// Get Signature-Input header
	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		return &VerificationResult{Verified: false, Error: fmt.Errorf("missing Signature-Input header")}
	}

	// Get Signature header
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		return &VerificationResult{Verified: false, Error: fmt.Errorf("missing Signature header")}
	}

	// Parse Signature-Input (simplified parsing for sig1=...)
	sigInput = strings.TrimPrefix(sigInput, "sig1=")

	// Extract keyid
	keyID, err := extractKeyID(sigInput)
	if err != nil {
		return &VerificationResult{Verified: false, Error: fmt.Errorf("failed to extract keyid: %w", err)}
	}

	// Extract covered components
	components, err := extractComponents(sigInput)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: keyID, Error: fmt.Errorf("failed to extract components: %w", err)}
	}

	// Get public key
	pubKey, err := publicKeyFetcher(keyID)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: keyID, Error: fmt.Errorf("failed to get public key: %w", err)}
	}

	// Parse signature value (remove sig1= prefix and decode base64)
	sigValue := strings.TrimPrefix(sigHeader, "sig1=:")
	sigValue = strings.TrimSuffix(sigValue, ":")
	sig, err := base64.StdEncoding.DecodeString(sigValue)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: keyID, Error: fmt.Errorf("invalid signature encoding: %w", err)}
	}

	// Rebuild signature base
	sigBase, err := buildSignatureBaseFromRequest(req, body, components)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: keyID, Error: fmt.Errorf("failed to build signature base: %w", err)}
	}

	// Complete with @signature-params
	fullBase := sigBase + fmt.Sprintf("\"@signature-params\": %s", sigInput)

	// Verify
	if ed25519.Verify(pubKey, []byte(fullBase), sig) {
		return &VerificationResult{Verified: true, KeyID: keyID}
	}

	return &VerificationResult{Verified: false, KeyID: keyID, Error: fmt.Errorf("signature verification failed")}
}

// HasSignatureHeaders checks if the request has signature headers.
func (v *RFC9421Verifier) HasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature-Input") != "" || req.Header.Get("Signature") != ""
}

// buildSignatureBaseFromRequest builds the signature base for verification.
func buildSignatureBaseFromRequest(req *http.Request, body []byte, components []string) (string, error) {
	var lines []string

	for _, comp := range components {
		var value string

		switch comp {
		case "@method":
			value = req.Method
		case "@target-uri":
			value = req.URL.String()
		case "@authority":
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		case "@path":
			value = req.URL.Path
		case "@query":
			value = "?" + req.URL.RawQuery
		default:
			// Regular header
			value = req.Header.Get(comp)
		}

		lines = append(lines, fmt.Sprintf("\"%s\": %s", comp, value))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// extractKeyID extracts the keyid from signature params.
func extractKeyID(sigParams string) (string, error) {
	// Find keyid="..."
	idx := strings.Index(sigParams, "keyid=\"")
	if idx == -1 {
		return "", fmt.Errorf("keyid not found in signature params")
	}

	start := idx + len("keyid=\"")
	end := strings.Index(sigParams[start:], "\"")
	if end == -1 {
		return "", fmt.Errorf("malformed keyid")
	}

	return sigParams[start : start+end], nil
}

// extractComponents extracts the covered components from signature params.
func extractComponents(sigParams string) ([]string, error) {
	// Find (component1 component2 ...)
	start := strings.Index(sigParams, "(")
	end := strings.Index(sigParams, ")")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("malformed component list")
	}

	componentStr := sigParams[start+1 : end]
	parts := strings.Split(componentStr, " ")

	var components []string
	for _, p := range parts {
		p = strings.Trim(p, "\"")
		if p != "" {
			components = append(components, p)
		}
	}

	return components, nil
}

// computeSHA256Digest computes a SHA-256 digest and returns base64.
func computeSHA256Digest(data []byte) string {
	h := sha256Sum(data)
	return base64.StdEncoding.EncodeToString(h)
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// VerifyContentDigest verifies the Content-Digest header matches the body.
func VerifyContentDigest(req *http.Request, body []byte) error {
	digestHeader := req.Header.Get("Content-Digest")
	if digestHeader == "" {
		return nil // No digest to verify
	}

	// Parse sha-256=:base64:
	if !strings.HasPrefix(digestHeader, "sha-256=:") {
		return fmt.Errorf("unsupported digest algorithm")
	}

	digestB64 := strings.TrimPrefix(digestHeader, "sha-256=:")
	digestB64 = strings.TrimSuffix(digestB64, ":")

	expected, err := base64.StdEncoding.DecodeString(digestB64)
	if err != nil {
		return fmt.Errorf("invalid digest encoding: %w", err)
	}

	actual := sha256Sum(body)
	if !bytes.Equal(expected, actual) {
		return fmt.Errorf("content digest mismatch")
	}

	return nil
}

// ReadAndRestoreBody reads the request body and restores it for re-reading.
func ReadAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body.Close()

	// Restore body for downstream handlers
	req.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// SignedHTTPClient wraps an http.Client to sign outgoing requests.
type SignedHTTPClient struct {
	client     *http.Client
	signer     *RFC9421Signer
	peerCheck  func(host string) bool // returns true if peer is signing-capable
}

// NewSignedHTTPClient creates a new signing HTTP client.
func NewSignedHTTPClient(client *http.Client, signer *RFC9421Signer, peerCheck func(host string) bool) *SignedHTTPClient {
	return &SignedHTTPClient{
		client:    client,
		signer:    signer,
		peerCheck: peerCheck,
	}
}

// Do executes an HTTP request, signing it if the peer is signing-capable.
func (c *SignedHTTPClient) Do(req *http.Request, body []byte) (*http.Response, error) {
	// Check if peer is signing-capable
	host := req.URL.Host
	if c.peerCheck != nil && c.peerCheck(host) {
		// Sign the request
		if err := c.signer.SignRequest(req, body); err != nil {
			// If we intended to sign but failed, the request must fail
			return nil, fmt.Errorf("signing failed for signing-capable peer: %w", err)
		}
	}

	return c.client.Do(req)
}
