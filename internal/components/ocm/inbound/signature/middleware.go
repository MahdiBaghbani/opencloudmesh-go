// Package signature verifies inbound OCM HTTP request signatures.
package signature

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// contextKey is used for storing values in request context.
type contextKey string

const (
	// PeerIdentityKey is the context key for peer identity.
	PeerIdentityKey contextKey = "peer_identity"
)

// PeerIdentity represents the authenticated or declared peer identity.
type PeerIdentity struct {
	// Authority is the raw authority from keyId (lowercased host[:port]) if
	// verified, otherwise the raw declared peer authority.
	Authority string
	// AuthorityForCompare is the scheme-aware normalized authority for identity
	// comparison (default ports stripped).
	AuthorityForCompare string
	// Authenticated is true if the identity was verified via signature.
	Authenticated bool
	// KeyID is the keyId from the signature (if any).
	KeyID string
}

// GetPeerIdentity retrieves the peer identity from request context.
func GetPeerIdentity(ctx context.Context) *PeerIdentity {
	if pi, ok := ctx.Value(PeerIdentityKey).(*PeerIdentity); ok {
		return pi
	}
	return nil
}

// PeerDiscovery provides peer discovery information for signature verification.
type PeerDiscovery interface {
	// IsSigningCapable returns true if peer discovery says unsigned OCM requests
	// should be rejected on the signature axis.
	IsSigningCapable(ctx context.Context, host string) (bool, error)
	// ResolveVerificationKey fetches verification key material for a keyId.
	ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error)
}

// SignatureMiddleware verifies HTTP request signatures.
type SignatureMiddleware struct {
	inboundMode        string
	allowMismatch      bool
	peerContract       *peercompat.CompiledContract
	compatibilityScope string
	verifier           *crypto.RFC9421Verifier
	peerDiscovery      PeerDiscovery
	logger             *slog.Logger
	localScheme        string // scheme from PublicOrigin for unverified peer normalization
}

// NewSignatureMiddleware creates a new signature verification middleware.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
func NewSignatureMiddleware(
	runtimePolicy *policy.RuntimePolicy,
	peerContract *peercompat.CompiledContract,
	pd PeerDiscovery,
	publicOrigin string,
	sigCfg config.SignatureConfig,
	logger *slog.Logger,
) *SignatureMiddleware {
	logger = logutil.NoopIfNil(logger)

	localScheme := config.SchemeFromOrigin(publicOrigin)
	inboundMode := "off"
	allowMismatch := false
	compatibilityScope := "none"
	if runtimePolicy != nil {
		eval := runtimePolicy.Evaluate()
		signature := eval.Signature
		if signature.InboundMode != "" {
			inboundMode = signature.InboundMode
		}
		allowMismatch = signature.AllowMismatch
		if eval.CompatibilityScope != "" {
			compatibilityScope = eval.CompatibilityScope
		}
	}

	return &SignatureMiddleware{
		inboundMode:        inboundMode,
		allowMismatch:      allowMismatch,
		peerContract:       peerContract,
		compatibilityScope: compatibilityScope,
		verifier: crypto.NewRFC9421VerifierWithOptions(
			crypto.RFC9421OptionsFromConfig(sigCfg),
		),
		peerDiscovery: pd,
		logger:        logger,
		localScheme:   localScheme,
	}
}

func (m *SignatureMiddleware) logCompatibilityDecision(
	r *http.Request,
	level slog.Level,
	message string,
	entry peercompat.CompatibilityDecisionLog,
	extraAttrs ...any,
) {
	if reqID := chimw.GetReqID(r.Context()); reqID != "" {
		entry.RequestID = reqID
	}
	attrs := entry.SlogAttrs()
	if len(extraAttrs) > 0 {
		attrs = append(attrs, extraAttrs...)
	}
	m.logger.Log(r.Context(), level, message, attrs...)
}

func (m *SignatureMiddleware) decisionCompatibilityScope(profile string) string {
	if profile != "" && profile != "strict" {
		return "scoped"
	}
	if m.compatibilityScope != "" {
		return m.compatibilityScope
	}
	return "none"
}

// VerifyOCMRequestIfPresent verifies inbound signatures when present and
// populates peer identity from a verified keyId. Unsigned requests pass through
// without identity regardless of inbound mode. Invalid signatures are rejected.
func (m *SignatureMiddleware) VerifyOCMRequestIfPresent() func(http.Handler) http.Handler {
	return m.verifyOCMRequest(nil, false, false, true)
}

// VerifyOCMRequest is middleware for /ocm/* endpoints.
// declaredPeerResolver extracts the declared peer from the request body.
// When a resolver is present, malformed or missing declared peers return
// HTTP 400.
func (m *SignatureMiddleware) VerifyOCMRequest(declaredPeerResolver func(r *http.Request, body []byte) (string, error)) func(http.Handler) http.Handler {
	return m.verifyOCMRequest(declaredPeerResolver, false, false, false)
}

// VerifyOCMRequestRequireSignature enforces a verified signature even when
// inbound mode is off or lenient. Routes that pass a nil declaredPeerResolver
// (for example notifications) stay signature-only: trust is bound to keyId,
// not a body-declared peer.
func (m *SignatureMiddleware) VerifyOCMRequestRequireSignature(
	declaredPeerResolver func(r *http.Request, body []byte) (string, error),
) func(http.Handler) http.Handler {
	return m.verifyOCMRequest(declaredPeerResolver, true, false, false)
}

// VerifyOCMRequestRequireSignatureAndPeer enforces a verified signature and a
// non-empty declared peer from the request body. Use on shares, invites, and
// token routes where keyId must bind to the body-declared peer.
func (m *SignatureMiddleware) VerifyOCMRequestRequireSignatureAndPeer(
	declaredPeerResolver func(r *http.Request, body []byte) (string, error),
) func(http.Handler) http.Handler {
	return m.verifyOCMRequest(declaredPeerResolver, true, true, false)
}

func (m *SignatureMiddleware) verifyOCMRequest(
	declaredPeerResolver func(r *http.Request, body []byte) (string, error),
	requireSignature bool,
	requireDeclaredPeer bool,
	optionalSignature bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// off skips verification only when the route does not require a
			// signature and does not use verify-if-present semantics.
			if m.inboundMode == "off" && !requireSignature && !optionalSignature {
				next.ServeHTTP(w, r)
				return
			}

			// Read body for signature verification and peer resolution
			body, err := crypto.ReadAndRestoreBody(r)
			if err != nil {
				m.logger.Error("failed to read request body", "error", err)
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			if requireDeclaredPeer && declaredPeerResolver == nil {
				m.logger.Error("requireDeclaredPeer set without declared peer resolver")
				http.Error(w, "declared peer required", http.StatusBadRequest)
				return
			}

			// Extract declared peer from the request body when a resolver is set.
			var declaredPeer string
			if declaredPeerResolver != nil {
				declaredPeer, err = declaredPeerResolver(r, body)
				if err != nil {
					m.logger.Warn("failed to resolve declared peer", "error", err)
					http.Error(w, "invalid declared peer", http.StatusBadRequest)
					return
				}
				if strings.TrimSpace(declaredPeer) == "" {
					m.logger.Warn("missing declared peer")
					http.Error(w, "declared peer required", http.StatusBadRequest)
					return
				}
			}

			// Check for signature headers
			hasSignature := m.verifier.HasSignatureHeaders(r)

			// Get peer identity for context
			peerIdentity := &PeerIdentity{}

			if hasSignature {
				// Verify signature
				result := m.verifier.VerifyRequest(r, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
					return m.peerDiscovery.ResolveVerificationKey(r.Context(), keyID)
				})

				if result.Verified {
					parsedKid, err := keyid.ParseKid(result.KeyID)
					if err != nil {
						m.logger.Error("failed to parse keyId", "keyId", result.KeyID, "error", err)
						http.Error(w, "invalid signature keyId", http.StatusUnauthorized)
						return
					}

					compareScheme := parsedKid.Scheme
					if compareScheme == "" {
						compareScheme = m.localScheme
					}
					keyAuthorityForCompare, err := authorityForCompareFromKid(parsedKid, compareScheme)
					if err != nil {
						m.logger.Error("failed to normalize keyId authority",
							"keyId", result.KeyID, "error", err)
						http.Error(w, "invalid signature keyId", http.StatusUnauthorized)
						return
					}

					// Check for mismatch between declared peer and keyId authority.
					peerDecision := m.peerContract.SignatureDecisionForPeer(declaredPeer)
					allowMismatch := m.allowMismatch || (peerDecision.Matched && peerDecision.AllowMismatchedHost)
					if declaredPeer != "" && !allowMismatch {
						normalizedDeclared, err := keyid.AuthorityForCompareFromDeclaredPeer(declaredPeer, compareScheme)
						if err != nil {
							m.logger.Warn("failed to normalize declared peer for comparison",
								"declared_peer", declaredPeer, "error", err)
							http.Error(w, "peer identity mismatch", http.StatusForbidden)
							return
						}
						if normalizedDeclared != keyAuthorityForCompare {
							m.logger.Warn("peer identity mismatch",
								"declared", normalizedDeclared,
								"key_id_authority", keyAuthorityForCompare)
							http.Error(w, "peer identity mismatch", http.StatusForbidden)
							return
						}
					}

					peerIdentity = &PeerIdentity{
						Authority:           parsedKid.Authority,
						AuthorityForCompare: keyAuthorityForCompare,
						Authenticated:       true,
						KeyID:               result.KeyID,
					}
				} else {
					bodyMsg := httpBodyForVerifyReason(result.Reason)
					status := httpStatusForVerifyReason(result.Reason)
					m.logger.Warn("signature verification failed",
						"error", result.Error,
						"keyId", result.KeyID,
						"reason", result.Reason)
					http.Error(w, bodyMsg, status)
					return
				}
			} else {
				// No signature present
				if optionalSignature {
					if err := crypto.VerifyContentDigest(r, body); err != nil {
						m.logger.Warn("content digest verification failed", "error", err)
						http.Error(w, "content digest mismatch", http.StatusBadRequest)
						return
					}
					next.ServeHTTP(w, r)
					return
				}

				if requireSignature || m.inboundMode == "strict" {
					http.Error(w, "signature required", http.StatusUnauthorized)
					return
				}

				// lenient mode - check if peer is signing-capable
				if m.inboundMode == "lenient" && declaredPeer != "" {
					isCapable, err := m.peerDiscovery.IsSigningCapable(r.Context(), declaredPeer)
					if err != nil {
						discoveryDecision := m.peerContract.ResolveDiscoveryFailure(declaredPeer)
						logEntry := peercompat.CompatibilityDecisionLog{
							PeerDomain:         discoveryDecision.PeerDomain,
							Profile:            discoveryDecision.Profile,
							Operation:          "unsigned_inbound_discovery",
							ReasonCode:         discoveryDecision.ReasonCode,
							CompatibilityScope: m.decisionCompatibilityScope(discoveryDecision.Profile),
						}
						if discoveryDecision.Allow {
							logEntry.Decision = "allow"
							m.logCompatibilityDecision(
								r,
								slog.LevelWarn,
								"peer discovery failed, allowing unsigned",
								logEntry,
								"error", err,
							)
						} else {
							logEntry.Decision = "reject"
							m.logCompatibilityDecision(
								r,
								slog.LevelError,
								"peer discovery failed",
								logEntry,
								"error", err,
							)
							http.Error(w, "peer discovery failed", http.StatusBadGateway)
							return
						}
					} else if isCapable {
						peerDecision := m.peerContract.SignatureDecisionForPeer(declaredPeer)
						logEntry := peercompat.CompatibilityDecisionLog{
							PeerDomain:         peerDecision.PeerDomain,
							Profile:            peerDecision.Profile,
							Operation:          "unsigned_inbound_capability",
							CompatibilityScope: m.decisionCompatibilityScope(peerDecision.Profile),
						}
						if !peerDecision.Matched || !peerDecision.AllowUnsignedInbound {
							// Peer is signing-capable and no matched compatibility relaxation applies.
							logEntry.Decision = "reject"
							logEntry.ReasonCode = "signing_capable_peer_requires_signature"
							m.logCompatibilityDecision(
								r,
								slog.LevelWarn,
								"signing-capable peer sent unsigned request",
								logEntry,
							)
							http.Error(w, "signature required from signing-capable peer", http.StatusUnauthorized)
							return
						}
						logEntry.Decision = "allow"
						logEntry.ReasonCode = "peer_allow_unsigned_inbound"
						m.logCompatibilityDecision(
							r,
							slog.LevelWarn,
							"signing-capable peer allowed unsigned by compatibility profile",
							logEntry,
						)
					}
				}

				// Set unverified peer identity
				var authorityForCompare string
				if declaredPeer != "" {
					normalized, err := keyid.AuthorityForCompareFromDeclaredPeer(declaredPeer, m.localScheme)
					if err != nil {
						m.logger.Warn("failed to normalize declared peer",
							"declared_peer", declaredPeer, "error", err)
						http.Error(w, "invalid declared peer", http.StatusBadRequest)
						return
					}
					authorityForCompare = normalized
				}

				peerIdentity = &PeerIdentity{
					Authority:           declaredPeer,
					AuthorityForCompare: authorityForCompare,
					Authenticated:       false,
				}
			}

			// Verify Content-Digest if present
			if err := crypto.VerifyContentDigest(r, body); err != nil {
				m.logger.Warn("content digest verification failed", "error", err)
				http.Error(w, "content digest mismatch", http.StatusBadRequest)
				return
			}

			// Store peer identity in context
			ctx := context.WithValue(r.Context(), PeerIdentityKey, peerIdentity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authorityForCompareFromKid(k keyid.Kid, scheme string) (string, error) {
	if k.Scheme != "" {
		scheme = k.Scheme
	}
	normalized, err := hostport.Normalize(k.Authority, scheme)
	if err != nil {
		return "", err
	}
	return normalized, nil
}

func httpBodyForVerifyReason(reason string) string {
	switch reason {
	case crypto.ReasonKeyNotFound:
		return "signature key not found"
	case crypto.ReasonKeyLookupFailed:
		return "signature key lookup failed"
	case crypto.ReasonAlgorithmRejected:
		return "signature algorithm rejected"
	case crypto.ReasonContentDigest:
		return "content digest mismatch"
	default:
		return "signature verification failed"
	}
}

func httpStatusForVerifyReason(reason string) int {
	switch reason {
	case crypto.ReasonKeyLookupFailed:
		return http.StatusBadGateway
	case crypto.ReasonContentDigest:
		return http.StatusBadRequest
	default:
		return http.StatusUnauthorized
	}
}
