// Package signature verifies inbound OCM HTTP request signatures.
package signature

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
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
	// ResolveVerificationKey fetches verification key material for a keyId.
	ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error)
}

// SignatureMiddleware verifies HTTP request signatures.
type SignatureMiddleware struct {
	verifier      *crypto.RFC9421Verifier
	peerDiscovery PeerDiscovery
	logger        *slog.Logger
	localScheme   string // scheme from PublicOrigin for unverified peer normalization
}

// NewSignatureMiddleware creates a new signature verification middleware.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
func NewSignatureMiddleware(
	pd PeerDiscovery,
	publicOrigin string,
	sigCfg config.SignatureConfig,
	logger *slog.Logger,
) *SignatureMiddleware {
	logger = logutil.NoopIfNil(logger)

	localScheme := config.SchemeFromOrigin(publicOrigin)

	return &SignatureMiddleware{
		verifier: crypto.NewRFC9421VerifierWithOptions(
			crypto.RFC9421OptionsFromConfig(sigCfg),
		),
		peerDiscovery: pd,
		logger:        logger,
		localScheme:   localScheme,
	}
}

// VerifyOCMRequestIfPresent verifies inbound signatures when present and
// populates peer identity from a verified keyId. Unsigned requests pass through
// without identity. Invalid signatures are rejected.
func (m *SignatureMiddleware) VerifyOCMRequestIfPresent() func(http.Handler) http.Handler {
	return m.verifyOCMRequest(nil, false, false, true)
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

					if declaredPeer != "" {
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

				if requireSignature {
					http.Error(w, "signature required", http.StatusUnauthorized)
					return
				}

				http.Error(w, "signature required", http.StatusUnauthorized)
				return
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
