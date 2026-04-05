package crypto

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
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
	// GetPublicKey fetches the public key for a keyId.
	GetPublicKey(ctx context.Context, keyID string) (string, error) // returns PEM
}

// SignatureMiddleware verifies HTTP request signatures.
type SignatureMiddleware struct {
	inboundMode        string
	allowMismatch      bool
	onDiscoveryErr     string
	peerContract       *peercompat.CompiledContract
	compatibilityScope string
	verifier           *RFC9421Verifier
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
	logger *slog.Logger,
) *SignatureMiddleware {
	logger = logutil.NoopIfNil(logger)

	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}
	inboundMode := "off"
	onDiscoveryErr := "reject"
	allowMismatch := false
	compatibilityScope := "none"
	if runtimePolicy != nil {
		eval := runtimePolicy.Evaluate()
		signature := eval.Signature
		if signature.InboundMode != "" {
			inboundMode = signature.InboundMode
		}
		if signature.OnDiscoveryError != "" {
			onDiscoveryErr = signature.OnDiscoveryError
		}
		allowMismatch = signature.AllowMismatch
		if eval.CompatibilityScope != "" {
			compatibilityScope = eval.CompatibilityScope
		}
	}

	return &SignatureMiddleware{
		inboundMode:        inboundMode,
		allowMismatch:      allowMismatch,
		onDiscoveryErr:     onDiscoveryErr,
		peerContract:       peerContract,
		compatibilityScope: compatibilityScope,
		verifier:           NewRFC9421Verifier(),
		peerDiscovery:      pd,
		logger:             logger,
		localScheme:        localScheme,
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

// VerifyOCMRequest is middleware for /ocm/* endpoints.
// declaredPeerResolver extracts the declared peer from the request body.
func (m *SignatureMiddleware) VerifyOCMRequest(declaredPeerResolver func(r *http.Request, body []byte) (string, error)) func(http.Handler) http.Handler {
	return m.verifyOCMRequest(declaredPeerResolver, false)
}

// VerifyOCMRequestRequireSignature enforces a verified signature whenever the
// signature axis is active, even if inbound mode is lenient.
func (m *SignatureMiddleware) VerifyOCMRequestRequireSignature(
	declaredPeerResolver func(r *http.Request, body []byte) (string, error),
) func(http.Handler) http.Handler {
	return m.verifyOCMRequest(declaredPeerResolver, true)
}

func (m *SignatureMiddleware) verifyOCMRequest(
	declaredPeerResolver func(r *http.Request, body []byte) (string, error),
	requireSignature bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If inbound mode is off, skip verification
			if m.inboundMode == "off" {
				next.ServeHTTP(w, r)
				return
			}

			// Read body for signature verification and peer resolution
			body, err := ReadAndRestoreBody(r)
			if err != nil {
				m.logger.Error("failed to read request body", "error", err)
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			// Extract declared peer from request body
			var declaredPeer string
			if declaredPeerResolver != nil {
				declaredPeer, err = declaredPeerResolver(r, body)
				if err != nil {
					m.logger.Warn("failed to resolve declared peer", "error", err)
					// Continue - might be resolved from signature
				}
			}

			// Check for signature headers
			hasSignature := m.verifier.HasSignatureHeaders(r)

			// Get peer identity for context
			peerIdentity := &PeerIdentity{}

			if hasSignature {
				// Verify signature
				result := m.verifier.VerifyRequest(r, body, func(keyID string) (ed25519.PublicKey, error) {
					pemData, err := m.peerDiscovery.GetPublicKey(r.Context(), keyID)
					if err != nil {
						return nil, err
					}
					return ParsePublicKeyPEM(pemData)
				})

				if result.Verified {
					// Parse keyId using canonical keyid module
					parsed, err := keyid.Parse(result.KeyID)
					if err != nil {
						m.logger.Error("failed to parse keyId", "keyId", result.KeyID, "error", err)
						http.Error(w, "invalid signature keyId", http.StatusBadRequest)
						return
					}

					// Check for mismatch between declared peer and keyId authority.
					peerDecision := m.peerContract.SignatureDecisionForPeer(declaredPeer)
					allowMismatch := m.allowMismatch || (peerDecision.Matched && peerDecision.AllowMismatchedHost)
					if declaredPeer != "" && !allowMismatch {
						normalizedDeclared, err := keyid.AuthorityForCompareFromDeclaredPeer(declaredPeer, parsed.Scheme)
						if err != nil {
							m.logger.Warn("failed to normalize declared peer for comparison",
								"declared_peer", declaredPeer, "error", err)
							// Skip mismatch enforcement on error (no new rejection path)
						} else if normalizedDeclared != keyid.AuthorityForCompareFromKeyID(parsed) {
							m.logger.Warn("peer identity mismatch",
								"declared", normalizedDeclared,
								"key_id_authority", keyid.AuthorityForCompareFromKeyID(parsed))
							http.Error(w, "peer identity mismatch", http.StatusForbidden)
							return
						}
					}

					peerIdentity = &PeerIdentity{
						Authority:           keyid.Authority(parsed),
						AuthorityForCompare: keyid.AuthorityForCompareFromKeyID(parsed),
						Authenticated:       true,
						KeyID:               result.KeyID,
					}
				} else {
					// Signature present but verification failed - always reject
					m.logger.Warn("signature verification failed",
						"error", result.Error,
						"keyId", result.KeyID)
					http.Error(w, "signature verification failed", http.StatusUnauthorized)
					return
				}
			} else {
				// No signature present
				if requireSignature || m.inboundMode == "strict" {
					http.Error(w, "signature required", http.StatusUnauthorized)
					return
				}

				// lenient mode - check if peer is signing-capable
				if m.inboundMode == "lenient" && declaredPeer != "" {
					isCapable, err := m.peerDiscovery.IsSigningCapable(r.Context(), declaredPeer)
					if err != nil {
						discoveryDecision := m.peerContract.ResolveDiscoveryFailure(declaredPeer, m.onDiscoveryErr)
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
						authorityForCompare = declaredPeer // fallback to raw
					} else {
						authorityForCompare = normalized
					}
				}

				peerIdentity = &PeerIdentity{
					Authority:           declaredPeer,
					AuthorityForCompare: authorityForCompare,
					Authenticated:       false,
				}
			}

			// Verify Content-Digest if present
			if err := VerifyContentDigest(r, body); err != nil {
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
