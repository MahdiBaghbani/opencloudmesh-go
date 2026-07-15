package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

const httpTimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// RFC9421Options holds signer and verifier policy derived from config.
type RFC9421Options struct {
	Label              string
	CreatedMaxAge      time.Duration
	CreatedMaxSkew     time.Duration
	AllowedAlgorithms  []string
	RequiredComponents []string
	Now                func() time.Time
}

// DefaultRFC9421Options returns OCM IETF Appendix B defaults.
func DefaultRFC9421Options() RFC9421Options {
	return RFC9421OptionsFromConfig(config.DefaultSignatureConfig())
}

// RFC9421OptionsFromConfig maps signature config to signer/verifier options.
func RFC9421OptionsFromConfig(sig config.SignatureConfig) RFC9421Options {
	label := sig.Label
	if label == "" {
		label = config.DefaultSignatureLabel
	}
	maxAge := time.Duration(sig.CreatedMaxAgeSeconds) * time.Second
	if maxAge <= 0 {
		maxAge = time.Duration(config.DefaultSignatureCreatedMaxAge) * time.Second
	}
	maxSkew := time.Duration(sig.CreatedMaxSkewSeconds) * time.Second
	if sig.CreatedMaxSkewSeconds == 0 {
		maxSkew = time.Duration(config.DefaultSignatureCreatedMaxSkew) * time.Second
	}
	allowed := sig.AllowedAlgorithms
	if len(allowed) == 0 {
		allowed = sigalg.DefaultAllowed()
	}
	return RFC9421Options{
		Label:              label,
		CreatedMaxAge:      maxAge,
		CreatedMaxSkew:     maxSkew,
		AllowedAlgorithms:  append([]string(nil), allowed...),
		RequiredComponents: AppendixBCoveredComponents(),
		Now:                time.Now,
	}
}

// AppendixBCoveredComponents returns the OCM IETF Appendix B covered set.
func AppendixBCoveredComponents() []string {
	return []string{
		"@method",
		"@target-uri",
		"content-digest",
		"content-length",
		"date",
	}
}

// RFC9421Signer signs HTTP requests per RFC 9421 using the OCM label.
type RFC9421Signer struct {
	keyManager *KeyManager
	opts       RFC9421Options
}

// NewRFC9421Signer creates a signer with default OCM options.
func NewRFC9421Signer(km *KeyManager) *RFC9421Signer {
	return NewRFC9421SignerWithOptions(km, DefaultRFC9421Options())
}

// NewRFC9421SignerWithOptions creates a signer with explicit options.
func NewRFC9421SignerWithOptions(km *KeyManager, opts RFC9421Options) *RFC9421Signer {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Label == "" {
		opts.Label = config.DefaultSignatureLabel
	}
	if len(opts.AllowedAlgorithms) == 0 {
		opts.AllowedAlgorithms = sigalg.DefaultAllowed()
	}
	if len(opts.RequiredComponents) == 0 {
		opts.RequiredComponents = AppendixBCoveredComponents()
	}
	return &RFC9421Signer{keyManager: km, opts: opts}
}

// SignRequest signs an HTTP request per RFC 9421.
func (s *RFC9421Signer) SignRequest(req *http.Request, body []byte) error {
	key := s.keyManager.GetSigningKey()
	if key == nil {
		return fmt.Errorf("no signing key available")
	}

	if err := sigalg.ValidateAllowed(key.Algorithm, s.opts.AllowedAlgorithms); err != nil {
		return err
	}

	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", s.opts.Now().UTC().Format(httpTimeFormat))
	}

	if len(body) > 0 {
		digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
		req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:", digest))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	components := s.presentComponents(req, s.opts.RequiredComponents)
	created := s.opts.Now().Unix()

	sigInput := sigparams.FormatSignatureInput(
		s.opts.Label,
		components,
		created,
		key.KeyID,
		key.Algorithm,
	)
	sigParamsValue := strings.TrimPrefix(sigInput, s.opts.Label+"=")

	sigBase, err := buildSignatureBase(req, components)
	if err != nil {
		return fmt.Errorf("failed to build signature base: %w", err)
	}
	fullBase := sigBase + fmt.Sprintf("\"@signature-params\": %s", sigParamsValue)

	sig, err := s.keyManager.Sign([]byte(fullBase))
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sigparams.FormatSignature(s.opts.Label, sig))
	return nil
}

// Sign satisfies tokenoutgoing.RequestSigner by reading and restoring the
// request body, then delegating to SignRequest.
func (s *RFC9421Signer) Sign(req *http.Request) error {
	body, err := ReadAndRestoreBody(req)
	if err != nil {
		return fmt.Errorf("failed to read request body for signing: %w", err)
	}
	return s.SignRequest(req, body)
}

func (s *RFC9421Signer) presentComponents(req *http.Request, components []string) []string {
	return PresentComponents(req, components)
}

// PresentComponents returns Appendix B components the signer includes for req.
// Derived components are always present; header components appear only when set.
func PresentComponents(req *http.Request, components []string) []string {
	actual := make([]string, 0, len(components))
	for _, comp := range components {
		comp = strings.ToLower(comp)
		if strings.HasPrefix(comp, "@") {
			actual = append(actual, comp)
			continue
		}
		if req.Header.Get(comp) != "" {
			actual = append(actual, comp)
		}
	}
	return actual
}

// RFC9421Verifier verifies HTTP request signatures per RFC 9421.
type RFC9421Verifier struct {
	opts RFC9421Options
}

// NewRFC9421Verifier creates a verifier with default OCM options.
func NewRFC9421Verifier() *RFC9421Verifier {
	return NewRFC9421VerifierWithOptions(DefaultRFC9421Options())
}

// NewRFC9421VerifierWithOptions creates a verifier with explicit options.
func NewRFC9421VerifierWithOptions(opts RFC9421Options) *RFC9421Verifier {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Label == "" {
		opts.Label = config.DefaultSignatureLabel
	}
	if len(opts.AllowedAlgorithms) == 0 {
		opts.AllowedAlgorithms = sigalg.DefaultAllowed()
	}
	if len(opts.RequiredComponents) == 0 {
		opts.RequiredComponents = AppendixBCoveredComponents()
	}
	return &RFC9421Verifier{opts: opts}
}

// Verification reason codes for middleware HTTP body mapping.
const (
	ReasonMalformed         = "malformed"
	ReasonMissingCreated    = "missing_created"
	ReasonFutureCreated     = "future_created"
	ReasonStaleCreated      = "stale_created"
	ReasonMissingComponent  = "missing_component"
	ReasonKeyNotFound       = "key_not_found"
	ReasonKeyLookupFailed   = "key_lookup_failed"
	ReasonAlgorithmRejected = "algorithm_rejected"
	ReasonCryptoFail        = "crypto_fail"
)

// VerificationResult contains the result of signature verification.
type VerificationResult struct {
	Verified bool
	KeyID    string
	Error    error
	Reason   string
}

// VerifyRequest verifies an HTTP request signature.
func (v *RFC9421Verifier) VerifyRequest(
	req *http.Request,
	body []byte,
	keyFetcher func(keyID string) (sigalg.ResolvedPublicKey, error),
) *VerificationResult {
	sigInputHeader := req.Header.Get("Signature-Input")
	if sigInputHeader == "" {
		return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("missing Signature-Input header")}
	}

	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("missing Signature header")}
	}

	if sigparams.CountDictionaryMembers(sigInputHeader, v.opts.Label) > 1 {
		return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("multiple %q signatures", v.opts.Label)}
	}
	if sigparams.CountDictionaryMembers(sigHeader, v.opts.Label) > 1 {
		return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("multiple %q signatures", v.opts.Label)}
	}

	params, err := sigparams.ParseSignatureInput(sigInputHeader, v.opts.Label)
	if err != nil {
		return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("failed to parse Signature-Input: %w", err)}
	}

	sig, err := sigparams.ParseSignature(sigHeader, v.opts.Label)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMalformed, Error: err}
	}

	if params.Created == 0 {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMissingCreated, Error: fmt.Errorf("missing created parameter")}
	}
	if reason, err := v.validateCreated(params.Created); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: reason, Error: err}
	}

	expectedComponents := PresentComponents(req, v.opts.RequiredComponents)
	if err := validateRequiredComponents(params.Components, expectedComponents); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMissingComponent, Error: err}
	}

	resolvedKey, err := keyFetcher(params.KeyID)
	if err != nil {
		reason := ReasonKeyLookupFailed
		if errors.Is(err, jwks.ErrKeyNotFound) {
			reason = ReasonKeyNotFound
		}
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: reason, Error: fmt.Errorf("failed to get public key: %w", err)}
	}

	resolvedAlg, err := sigalg.ResolveAlgorithm(params.Algorithm, resolvedKey.JWKKty, resolvedKey.JWKCrv, resolvedKey.JWKAlg)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonAlgorithmRejected, Error: err}
	}
	if err := sigalg.ValidateAllowed(resolvedAlg, v.opts.AllowedAlgorithms); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonAlgorithmRejected, Error: err}
	}

	sigBase, err := buildSignatureBaseFromRequest(req, body, params.Components)
	if err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMalformed, Error: fmt.Errorf("failed to build signature base: %w", err)}
	}

	fullBase := sigBase + fmt.Sprintf("\"@signature-params\": %s", params.Raw)

	if err := sigalg.Verify(resolvedAlg, resolvedKey.PublicKey, []byte(fullBase), sig); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonCryptoFail, Error: fmt.Errorf("signature verification failed: %w", err)}
	}

	return &VerificationResult{Verified: true, KeyID: params.KeyID}
}

func (v *RFC9421Verifier) validateCreated(created int64) (string, error) {
	now := v.opts.Now().Unix()
	maxSkew := int64(v.opts.CreatedMaxSkew / time.Second)
	maxAge := int64(v.opts.CreatedMaxAge / time.Second)
	if created > now+maxSkew {
		return ReasonFutureCreated, fmt.Errorf("created timestamp is too far in the future")
	}
	if now-created > maxAge {
		return ReasonStaleCreated, fmt.Errorf("created timestamp is stale")
	}
	return "", nil
}

func validateRequiredComponents(actual, required []string) error {
	present := map[string]struct{}{}
	for _, c := range actual {
		present[strings.ToLower(c)] = struct{}{}
	}
	for _, reqComp := range required {
		if _, ok := present[strings.ToLower(reqComp)]; !ok {
			return fmt.Errorf("missing required signature component %q", reqComp)
		}
	}
	return nil
}

// HasSignatureHeaders checks if the request has signature headers.
func (v *RFC9421Verifier) HasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature-Input") != "" || req.Header.Get("Signature") != ""
}

func buildSignatureBase(req *http.Request, components []string) (string, error) {
	var lines []string
	for _, comp := range components {
		comp = strings.ToLower(comp)
		value, err := componentValue(req, comp, false)
		if err != nil {
			return "", err
		}
		if err := rejectCRLF(comp, value); err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("\"%s\": %s", comp, value))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// BuildSignatureBase builds RFC 9421 signature-base lines for components
// (without the trailing @signature-params line).
func BuildSignatureBase(req *http.Request, components []string) (string, error) {
	return buildSignatureBase(req, components)
}

func buildSignatureBaseFromRequest(req *http.Request, _ []byte, components []string) (string, error) {
	var lines []string
	for _, comp := range components {
		comp = strings.ToLower(comp)
		value, err := componentValue(req, comp, true)
		if err != nil {
			return "", err
		}
		if err := rejectCRLF(comp, value); err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("\"%s\": %s", comp, value))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func rejectCRLF(comp, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("component %q value contains CR/LF", comp)
	}
	return nil
}

func componentValue(req *http.Request, comp string, received bool) (string, error) {
	switch comp {
	case "@method":
		return req.Method, nil
	case "@target-uri":
		return CanonicalTargetURI(req), nil
	case "@authority":
		value := req.Host
		if value == "" {
			value = req.URL.Host
		}
		return value, nil
	case "@path":
		return req.URL.Path, nil
	case "@query":
		if req.URL.RawQuery == "" {
			return "?", nil
		}
		return "?" + req.URL.RawQuery, nil
	case "content-digest":
		return req.Header.Get("content-digest"), nil
	case "content-length":
		return req.Header.Get("content-length"), nil
	case "date":
		return req.Header.Get("date"), nil
	default:
		value := req.Header.Get(comp)
		if value == "" && received {
			return "", fmt.Errorf("missing header %q", comp)
		}
		return value, nil
	}
}

// CanonicalTargetURI returns one scheme://host+RequestURI form for both
// signing and verification so proxy-reconstructed requests stay consistent.
func CanonicalTargetURI(req *http.Request) string {
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	return scheme + "://" + host + req.URL.RequestURI()
}

// VerifyContentDigest verifies the Content-Digest header matches the body.
func VerifyContentDigest(req *http.Request, body []byte) error {
	digestHeader := req.Header.Get("Content-Digest")
	if digestHeader == "" {
		return nil
	}

	if !strings.HasPrefix(digestHeader, "sha-256=:") {
		return fmt.Errorf("unsupported digest algorithm")
	}

	digestB64 := strings.TrimPrefix(digestHeader, "sha-256=:")
	digestB64 = strings.TrimSuffix(digestB64, ":")

	expected, err := base64.StdEncoding.DecodeString(digestB64)
	if err != nil {
		return fmt.Errorf("invalid digest encoding: %w", err)
	}

	actual := sigalg.SumSHA256(body)
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

	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}
