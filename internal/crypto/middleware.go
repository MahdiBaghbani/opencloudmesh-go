package crypto

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
)

// contextKey is used for storing values in request context.
type contextKey string

const (
	// PeerIdentityKey is the context key for peer identity.
	PeerIdentityKey contextKey = "peer_identity"
)

// PeerIdentity represents the authenticated or declared peer identity.
type PeerIdentity struct {
	// Host is the peer's host (from keyId if verified, from request if declared)
	Host string
	// Authenticated is true if the identity was verified via signature
	Authenticated bool
	// KeyID is the keyId from the signature (if any)
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
}

// NewSignatureMiddleware creates a new signature verification middleware.
func NewSignatureMiddleware(cfg *config.SignatureConfig, pd PeerDiscovery, logger *slog.Logger) *SignatureMiddleware {
	return &SignatureMiddleware{
		cfg:           cfg,
		verifier:      NewRFC9421Verifier(),
		peerDiscovery: pd,
		logger:        logger,
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
					// Extract host from keyId
					keyHost, err := ExtractHostFromKeyID(result.KeyID)
					if err != nil {
						m.logger.Error("failed to extract host from keyId", "keyId", result.KeyID, "error", err)
						http.Error(w, "invalid signature keyId", http.StatusBadRequest)
						return
					}

					// Check for mismatch between declared peer and keyId host
					if declaredPeer != "" && !m.cfg.AllowMismatch {
						declaredHost := normalizeHost(declaredPeer)
						if declaredHost != keyHost {
							m.logger.Warn("peer identity mismatch",
								"declared", declaredHost,
								"keyId_host", keyHost)
							http.Error(w, "peer identity mismatch", http.StatusForbidden)
							return
						}
					}

					peerIdentity = &PeerIdentity{
						Host:          keyHost,
						Authenticated: true,
						KeyID:         result.KeyID,
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
				peerIdentity = &PeerIdentity{
					Host:          normalizeHost(declaredPeer),
					Authenticated: false,
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

// normalizeHost normalizes a host string for comparison.
func normalizeHost(host string) string {
	host = strings.ToLower(host)
	// Remove default ports
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")
	return host
}
