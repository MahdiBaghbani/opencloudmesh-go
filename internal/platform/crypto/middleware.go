package crypto

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
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
	// IsSigningCapable returns true if the peer advertises http-sig capability.
	IsSigningCapable(ctx context.Context, host string) (bool, error)
	// GetPublicKey fetches the public key for a keyId.
	GetPublicKey(ctx context.Context, keyID string) (string, error) // returns PEM
}

// SignatureMiddleware verifies HTTP request signatures.
type SignatureMiddleware struct {
	cfg           *config.SignatureConfig
	verifier      *RFC9421Verifier
	peerDiscovery PeerDiscovery
	logger        *slog.Logger
	localScheme   string // scheme from PublicOrigin for unverified peer normalization
}

// NewSignatureMiddleware creates a new signature verification middleware.
// publicOrigin is the local instance's PublicOrigin (validated at config load).
func NewSignatureMiddleware(cfg *config.SignatureConfig, pd PeerDiscovery, externalOrigin string, logger *slog.Logger) *SignatureMiddleware {
	var localScheme string
	if u, err := url.Parse(externalOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &SignatureMiddleware{
		cfg:           cfg,
		verifier:      NewRFC9421Verifier(),
		peerDiscovery: pd,
		logger:        logger,
		localScheme:   localScheme,
	}
}

// VerifyOCMRequest is middleware for /ocm/* endpoints.
// declaredPeerResolver extracts the declared peer from the request body.
func (m *SignatureMiddleware) VerifyOCMRequest(declaredPeerResolver func(r *http.Request, body []byte) (string, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If inbound mode is off, skip verification
			if m.cfg.InboundMode == "off" {
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

					// Check for mismatch between declared peer and keyId authority
					if declaredPeer != "" && !m.cfg.AllowMismatch {
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
				if m.cfg.InboundMode == "strict" {
					http.Error(w, "signature required", http.StatusUnauthorized)
					return
				}

				// lenient mode - check if peer is signing-capable
				if m.cfg.InboundMode == "lenient" && declaredPeer != "" {
					isCapable, err := m.peerDiscovery.IsSigningCapable(r.Context(), declaredPeer)
					if err != nil {
						if m.cfg.OnDiscoveryError == "allow" {
							m.logger.Warn("peer discovery failed, allowing unsigned",
								"peer", declaredPeer, "error", err)
						} else {
							m.logger.Error("peer discovery failed",
								"peer", declaredPeer, "error", err)
							http.Error(w, "peer discovery failed", http.StatusBadGateway)
							return
						}
					} else if isCapable {
						// Peer is signing-capable but didn't sign - reject
						m.logger.Warn("signing-capable peer sent unsigned request",
							"peer", declaredPeer)
						http.Error(w, "signature required from signing-capable peer", http.StatusUnauthorized)
						return
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
