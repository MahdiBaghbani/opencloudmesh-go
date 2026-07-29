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
		label = sigparams.SignatureLabelOCM
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
	// RequiredComponents is intentionally left empty so signer and verifier
	// constructors apply role-specific defaults; both default to the
	// date-free canonical set in MandatorySignatureComponents(). The OCM
	// signing requirements deliberately exclude the Date header from the
	// covered components.
	// See:
	//   - Signing requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L833-L854
	//   - Verification requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L860-L864
	return RFC9421Options{
		Label:             label,
		CreatedMaxAge:     maxAge,
		CreatedMaxSkew:    maxSkew,
		AllowedAlgorithms: append([]string(nil), allowed...),
		Now:               time.Now,
	}
}

// AppendixBCoveredComponents returns the OCM IETF Appendix B covered set.
// It is a compatibility alias for MandatorySignatureComponents: the signing
// requirements deliberately exclude the Date header, so the covered set is
// date-free. See https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L833-L854
func AppendixBCoveredComponents() []string {
	return MandatorySignatureComponents()
}

// MandatorySignatureComponents is the single source of truth for the
// date-free canonical covered set. Signers default to covering exactly
// these components, and verifiers reject signatures that omit any of them
// or the created parameter. The Date header is deliberately not covered:
// intermediaries sometimes rewrite it, and the created parameter already
// conveys the message's creation time.
// See:
//   - Signing requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L833-L854
//   - Verification requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L860-L864
func MandatorySignatureComponents() []string {
	return []string{
		"@method",
		"@target-uri",
		"content-digest",
		"content-length",
	}
}

// hasDateComponent reports whether an explicit component list includes the
// date component.
func hasDateComponent(components []string) bool {
	for _, comp := range components {
		if strings.ToLower(comp) == "date" {
			return true
		}
	}

	return false
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
		opts.Label = sigparams.SignatureLabelOCM
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

	// The default covered set is date-free, so no Date header is created.
	// When an operator explicitly configures the date component, ensure a
	// Date header exists so the signer can actually cover it.
	if hasDateComponent(s.opts.RequiredComponents) && req.Header.Get("Date") == "" {
		req.Header.Set("Date", s.opts.Now().UTC().Format(http.TimeFormat))
	}

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", fmt.Sprintf("sha-256=:%s:", digest))
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

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
		opts.Label = sigparams.SignatureLabelOCM
	}

	if len(opts.AllowedAlgorithms) == 0 {
		opts.AllowedAlgorithms = sigalg.DefaultAllowed()
	}

	if len(opts.RequiredComponents) == 0 {
		opts.RequiredComponents = MandatorySignatureComponents()
	}

	return &RFC9421Verifier{opts: opts}
}

// Verification reason codes for middleware HTTP body mapping.
const (
	ReasonMalformed         = "malformed"
	ReasonMissingCreated    = "missing_created"
	ReasonMissingKeyID      = "missing_keyid"
	ReasonFutureCreated     = "future_created"
	ReasonStaleCreated      = "stale_created"
	ReasonMissingComponent  = "missing_component"
	ReasonKeyNotFound       = "key_not_found"
	ReasonKeyLookupFailed   = "key_lookup_failed"
	ReasonAlgorithmRejected = "algorithm_rejected"
	ReasonCryptoFail        = "crypto_fail"
	ReasonContentDigest     = "content_digest"
	ReasonUnsigned          = "unsigned"
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
	sigHeader := req.Header.Get("Signature")

	if result, done := checkSignatureHeaders(sigInputHeader, sigHeader); done {
		return result
	}

	label, result, done := findOCMSignatureLabel(sigInputHeader, sigHeader)
	if done {
		return result
	}

	params, sig, result, done := parseSignatureParams(sigInputHeader, sigHeader, label)
	if done {
		return result
	}

	if result, done := v.verifySignaturePolicy(req, body, params); done {
		return result
	}

	return v.verifySignature(req, body, params, sig, keyFetcher)
}

func checkSignatureHeaders(sigInputHeader, sigHeader string) (*VerificationResult, bool) {
	if sigInputHeader == "" && sigHeader == "" {
		return &VerificationResult{Verified: false, Reason: ReasonUnsigned, Error: fmt.Errorf("missing signature headers")}, true
	}

	if sigInputHeader == "" {
		if sigparams.HasOCMSignatureAttempt(sigHeader) {
			return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("missing Signature-Input header for OCM signature")}, true
		}

		return &VerificationResult{Verified: false, Reason: ReasonUnsigned, Error: fmt.Errorf("missing Signature-Input header")}, true
	}

	if sigHeader == "" {
		if sigparams.HasOCMSignatureAttempt(sigInputHeader) {
			return &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("missing Signature header for OCM signature")}, true
		}

		return &VerificationResult{Verified: false, Reason: ReasonUnsigned, Error: fmt.Errorf("missing Signature header")}, true
	}

	return nil, false
}

func findOCMSignatureLabel(sigInputHeader, sigHeader string) (string, *VerificationResult, bool) {
	// Tag-first lookup: identify the OCM signature by its tag parameter
	// rather than by the dictionary label. Zero matching tags means the
	// request is unsigned for OCM; more than one is malformed.
	tagCount := sigparams.CountTags(sigInputHeader, sigparams.SignatureTagOCM)
	if tagCount == 0 {
		if sigparams.HasOCMTagAttempt(sigInputHeader) || sigparams.HasOCMTagAttempt(sigHeader) {
			return "", &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("malformed OCM signature tag")}, true
		}

		return "", &VerificationResult{Verified: false, Reason: ReasonUnsigned, Error: fmt.Errorf("no tag=%q signature", sigparams.SignatureTagOCM)}, true
	}

	if tagCount > 1 {
		return "", &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("multiple tag=%q signatures", sigparams.SignatureTagOCM)}, true
	}

	label, err := sigparams.FindTaggedLabel(sigInputHeader, sigparams.SignatureTagOCM)
	if err != nil {
		return "", &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("failed to locate tag=%q signature: %w", sigparams.SignatureTagOCM, err)}, true
	}

	if err := sigparams.ValidateExactlyOneLabel(sigInputHeader, label); err != nil {
		return "", &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: err}, true
	}

	if err := sigparams.ValidateExactlyOneLabel(sigHeader, label); err != nil {
		return "", &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: err}, true
	}

	return label, nil, false
}

func parseSignatureParams(sigInputHeader, sigHeader, label string) (sigparams.Params, []byte, *VerificationResult, bool) {
	params, err := sigparams.ParseSignatureInput(sigInputHeader, label)
	if err != nil {
		return sigparams.Params{}, nil, &VerificationResult{Verified: false, Reason: ReasonMalformed, Error: fmt.Errorf("failed to parse Signature-Input: %w", err)}, true
	}

	sig, err := sigparams.ParseSignature(sigHeader, label)
	if err != nil {
		return sigparams.Params{}, nil, &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMalformed, Error: err}, true
	}

	if params.Created == 0 {
		return params, nil, &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMissingCreated, Error: fmt.Errorf("missing created parameter")}, true
	}

	// The keyid parameter is mandatory and selects the verification key, so a
	// missing keyid fails here, before any JWKS resolution or network access.
	// See https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L842-L848
	if params.KeyID == "" {
		return params, nil, &VerificationResult{Verified: false, Reason: ReasonMissingKeyID, Error: fmt.Errorf("missing keyid parameter")}, true
	}

	return params, sig, nil, false
}

func (v *RFC9421Verifier) verifySignaturePolicy(req *http.Request, body []byte, params sigparams.Params) (*VerificationResult, bool) {
	if reason, err := v.validateCreated(params.Created); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: reason, Error: err}, true
	}

	// Verifier uses its configured mandatory component set (date-free per
	// MandatorySignatureComponents). The Date header is deliberately not
	// covered, so it is not required here.
	// See:
	//   - Signing requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L833-L854
	//   - Verification requirements: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L860-L864
	expectedComponents := v.opts.RequiredComponents
	if err := validateRequiredComponents(params.Components, expectedComponents); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonMissingComponent, Error: err}, true
	}

	if err := verifyRequiredBodyHeaders(req, body, expectedComponents); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonContentDigest, Error: err}, true
	}

	if err := VerifyContentDigest(req, body); err != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonContentDigest, Error: err}, true
	}

	return nil, false
}

func (v *RFC9421Verifier) verifySignature(
	req *http.Request,
	body []byte,
	params sigparams.Params,
	sig []byte,
	keyFetcher func(keyID string) (sigalg.ResolvedPublicKey, error),
) *VerificationResult {
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

	if validateErr := sigalg.ValidateAllowed(resolvedAlg, v.opts.AllowedAlgorithms); validateErr != nil {
		return &VerificationResult{Verified: false, KeyID: params.KeyID, Reason: ReasonAlgorithmRejected, Error: validateErr}
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

func verifyRequiredBodyHeaders(req *http.Request, body []byte, requiredComponents []string) error {
	required := map[string]struct{}{}
	for _, comp := range requiredComponents {
		required[strings.ToLower(comp)] = struct{}{}
	}

	if _, ok := required["content-digest"]; ok {
		if req.Header.Get("Content-Digest") == "" {
			return fmt.Errorf("missing Content-Digest header")
		}
	}

	if _, ok := required["content-length"]; ok {
		cl := req.Header.Get("Content-Length")
		if cl == "" {
			if len(body) > 0 {
				return fmt.Errorf("missing Content-Length header")
			}

			if req.ContentLength != 0 {
				return fmt.Errorf("content length mismatch")
			}

			return nil
		}

		n, err := strconv.Atoi(cl)
		if err != nil {
			return fmt.Errorf("invalid Content-Length header")
		}

		if n != len(body) {
			return fmt.Errorf("content length mismatch")
		}
	}

	return nil
}

// HasSignatureHeaders checks if the request has signature headers.
func (v *RFC9421Verifier) HasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature-Input") != "" || req.Header.Get("Signature") != ""
}

// HasOCMSignatureAttempt checks if the request has any OCM signature attempt
// by tag or label.
func (v *RFC9421Verifier) HasOCMSignatureAttempt(req *http.Request) bool {
	return sigparams.HasOCMSignatureAttempt(req.Header.Get("Signature-Input")) ||
		sigparams.HasOCMSignatureAttempt(req.Header.Get("Signature"))
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
		if v := req.Header.Get("content-length"); v != "" {
			return v, nil
		}

		return strconv.FormatInt(req.ContentLength, 10), nil
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
// When the header is absent, verification is skipped so optional unsigned
// paths can accept requests without a digest. When the header is present,
// every listed digest algorithm must be recognized and match the body per OCM
// IETF Appendix B.
func VerifyContentDigest(req *http.Request, body []byte) error {
	digestHeader := req.Header.Get("Content-Digest")
	if digestHeader == "" {
		return nil
	}

	entries, err := parseContentDigestHeader(digestHeader)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		hasher, ok := recognizedDigestHashers[entry.algorithm]
		if !ok {
			return fmt.Errorf("unsupported digest algorithm %q", entry.algorithm)
		}

		actual := hasher(body)
		if !bytes.Equal(entry.value, actual) {
			return fmt.Errorf("content digest mismatch for %s", entry.algorithm)
		}
	}

	return nil
}

type contentDigestEntry struct {
	algorithm string
	value     []byte
}

var recognizedDigestHashers = map[string]func([]byte) []byte{
	"sha-256": sigalg.SumSHA256,
	"sha-512": sigalg.SumSHA512,
}

func parseContentDigestHeader(header string) ([]contentDigestEntry, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, fmt.Errorf("empty Content-Digest header")
	}

	var entries []contentDigestEntry

	for memberStart := 0; memberStart < len(header); {
		memberStart = skipContentDigestSeparators(header, memberStart)
		if memberStart >= len(header) {
			break
		}

		memberEnd := scanContentDigestMemberEnd(header, memberStart)

		entry, err := parseContentDigestEntry(header[memberStart:memberEnd])
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry)

		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("malformed Content-Digest header")
	}

	return entries, nil
}

func skipContentDigestSeparators(header string, start int) int {
	for start < len(header) {
		ch := header[start]
		if ch == ' ' || ch == '\t' || ch == ',' {
			start++
			continue
		}

		break
	}

	return start
}

func parseContentDigestEntry(member string) (contentDigestEntry, error) {
	member = strings.TrimSpace(member)
	if member == "" {
		return contentDigestEntry{}, fmt.Errorf("malformed Content-Digest entry")
	}

	eq := strings.Index(member, "=")
	if eq <= 0 {
		return contentDigestEntry{}, fmt.Errorf("malformed Content-Digest entry %q", member)
	}

	algorithm := strings.TrimSpace(member[:eq])

	valuePart := strings.TrimSpace(member[eq+1:])
	if !strings.HasPrefix(valuePart, ":") || !strings.HasSuffix(valuePart, ":") {
		return contentDigestEntry{}, fmt.Errorf("malformed digest value for %s", algorithm)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.Trim(valuePart, ":"))
	if err != nil {
		return contentDigestEntry{}, fmt.Errorf("invalid digest encoding for %s: %w", algorithm, err)
	}

	return contentDigestEntry{algorithm: algorithm, value: raw}, nil
}

func scanContentDigestMemberEnd(header string, start int) int {
	inByteSeq := false

	for i := start; i < len(header); i++ {
		ch := header[i]
		if inByteSeq {
			if ch == ':' {
				inByteSeq = false
			}

			continue
		}

		if ch == ':' {
			inByteSeq = true
			continue
		}

		if ch == ',' {
			return i
		}
	}

	return len(header)
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

	//nolint:errcheck // best-effort cleanup; error is not actionable
	_ = req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}
