// Package shares provides the session-gated handler for POST /api/shares/outgoing (create shares to remote receivers).
package shares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Handler serves POST /api/shares/outgoing to create and send shares.
type Handler struct {
	repo            sharesoutgoing.OutgoingShareRepo
	discoveryClient *discovery.Client
	httpClient      httpclient.HTTPClient
	signer          *crypto.RFC9421Signer
	peerOrigin      *peerorigin.Resolver
	localProvider   string // raw host[:port] for owner/sender identity
	currentUser     func(context.Context) (*identity.User, error)
	logger          *slog.Logger
	allowedPaths    []string
}

// NewHandler returns a Handler with the given dependencies. Panics if discoveryClient is nil.
func NewHandler(
	repo sharesoutgoing.OutgoingShareRepo,
	discClient *discovery.Client,
	httpClient httpclient.HTTPClient,
	signer *crypto.RFC9421Signer,
	localProvider string,
	currentUser func(context.Context) (*identity.User, error),
	logger *slog.Logger,
) *Handler {
	if discClient == nil {
		panic("outgoingshares.NewHandler: discoveryClient must not be nil")
	}
	logger = logutil.NoopIfNil(logger)
	return &Handler{
		repo:            repo,
		discoveryClient: discClient,
		httpClient:      httpClient,
		signer:          signer,
		localProvider:   localProvider,
		currentUser:     currentUser,
		logger:          logger,
		allowedPaths:    []string{"/tmp", os.TempDir()},
	}
}

// SetAllowedPaths restricts localPath to the given directory prefixes.
func (h *Handler) SetAllowedPaths(paths []string) {
	h.allowedPaths = paths
}

// SetPeerOrigin wires the peer origin resolver used for receiver discovery.
func (h *Handler) SetPeerOrigin(peerOrigin *peerorigin.Resolver) {
	h.peerOrigin = peerOrigin
}

// HandleCreate handles POST /api/shares/outgoing.
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	var req sharesoutgoing.OutgoingShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, api.ReasonBadRequest, "failed to parse request")
		return
	}

	if req.ReceiverDomain == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "receiverDomain is required")
		return
	}
	if req.ShareWith == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareWith is required")
		return
	}
	if req.LocalPath == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "localPath is required")
		return
	}
	if len(req.Permissions) == 0 {
		api.WriteBadRequest(w, api.ReasonMissingField, "permissions is required")
		return
	}
	for _, perm := range req.Permissions {
		supported := false
		for _, allowed := range spec.SupportedWebDAVPermissions {
			if perm == allowed {
				supported = true
				break
			}
		}
		if !supported {
			api.WriteBadRequest(w, api.ReasonInvalidField, "permissions must be read-only")
			return
		}
	}

	cleanPath, err := h.validateLocalPath(req.LocalPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, err.Error())
		return
	}

	stat, err := os.Stat(cleanPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, "file does not exist")
		return
	}

	resourceType := req.ResourceType
	if resourceType == "" {
		if stat.IsDir() {
			resourceType = "folder"
		} else {
			resourceType = "file"
		}
	}

	name := req.Name
	if name == "" {
		name = filepath.Base(cleanPath)
	}

	providerID, _ := uuid.NewV7()
	webdavID, _ := uuid.NewV7()
	sharedSecret := generateSharedSecret()

	owner := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)

	receiverOrigin := h.resolvePeerOrigin(req.ReceiverDomain)
	if receiverOrigin.baseURL == "" || receiverOrigin.peerDomain == "" {
		h.logger.Warn("receiver origin resolution failed", "receiver", req.ReceiverDomain)
		api.WriteError(w, reason.APIStatus(reason.PeerDiscoveryFailed), reason.PeerDiscoveryFailed,
			"could not resolve receiver origin")
		return
	}
	disc, err := h.discoveryClient.Discover(r.Context(), receiverOrigin.baseURL)
	if err != nil {
		h.logger.Warn("receiver discovery failed", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, reason.APIStatus(reason.PeerDiscoveryFailed), reason.PeerDiscoveryFailed, "could not discover receiver")
		return
	}

	if !disc.SupportsTokenExchange() {
		h.logger.Warn("receiver lacks token-exchange capability",
			"receiver", req.ReceiverDomain)
		api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
			"receiver does not advertise exchange-token with tokenEndPoint")
		return
	}

	webdavURI := webdavID.String()
	if disc.WebDAVReceiveURIKind() == spec.WebDAVReceiveURIAbsolute {
		absURI, buildErr := disc.BuildWebDAVURL(webdavID.String())
		if buildErr != nil {
			h.logger.Warn("failed to build absolute webdav uri", "receiver", req.ReceiverDomain, "error", buildErr)
			api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
				"receiver webdav-receive absolute uri could not be built")
			return
		}
		if h.peerOrigin == nil || !h.peerOrigin.IsAbsoluteURIAllowed(absURI, req.ReceiverDomain) {
			h.logger.Warn("absolute webdav uri failed peer authority check",
				"receiver", req.ReceiverDomain, "uri", absURI)
			api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
				"receiver webdav-receive absolute uri failed authority check")
			return
		}
		webdavURI = absURI
	}

	webdavProto := &spec.WebDAVProtocol{
		URI:          webdavURI,
		SharedSecret: sharedSecret,
		Permissions:  req.Permissions,
		Requirements: []string{spec.RequirementMustExchangeToken},
	}

	payload := spec.NewShareRequest{
		ShareWith:    req.ShareWith,
		Name:         name,
		ProviderID:   providerID.String(),
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: resourceType,
		Protocol: spec.Protocol{
			Name:   "webdav",
			WebDAV: webdavProto,
		},
	}

	if err := h.sendShareToReceiver(r.Context(), receiverOrigin, disc, payload); err != nil {
		h.logger.Warn("failed to send share to receiver", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, http.StatusBadGateway, reason.PeerUnreachable, err.Error())
		return
	}

	now := time.Now()
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:       providerID.String(),
		WebDAVID:         webdavID.String(),
		SharedSecret:     sharedSecret,
		LocalPath:        cleanPath,
		ReceiverHost:     receiverOrigin.peerDomain,
		ReceiverEndPoint: disc.EndPoint,
		ShareWith:        req.ShareWith,
		Name:             name,
		ResourceType:     resourceType,
		ShareType:        "user",
		Permissions:      req.Permissions,
		Owner:            owner,
		Sender:           sender,
		Status:           "sent",
		SentAt:           &now,
	}

	if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store outgoing share", "error", err)
		api.WriteInternalError(w, "share sent but local persistence failed")
		return
	}

	h.logger.Info("outgoing share created and sent",
		"share_id", share.ShareID,
		"provider_id", share.ProviderID,
		"receiver", req.ReceiverDomain)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"shareId":    share.ShareID,
		"providerId": share.ProviderID,
		"webdavId":   share.WebDAVID,
		"status":     share.Status,
	})
}

// validateLocalPath ensures path is absolute, under allowedPaths, and has no traversal.
func (h *Handler) validateLocalPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)

	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must be absolute")
	}

	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}

	allowed := false
	for _, prefix := range h.allowedPaths {
		if strings.HasPrefix(cleanPath, prefix) {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("path not in allowed directories")
	}

	return cleanPath, nil
}

func (h *Handler) sendShareToReceiver(
	ctx context.Context,
	origin resolvedPeerOrigin,
	disc *discovery.Discovery,
	payload spec.NewShareRequest,
) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	poster := outbound.NewPoster(h.httpClient, h.discoveryClient, h.signer, h.peerOrigin)
	resp, err := poster.SendResolved(ctx, outbound.Request{
		TargetHost:   origin.peerDomain,
		EndpointPath: "shares",
		Kind:         outbound.EndpointShares,
		Body:         body,
	}, outbound.ResolvedPeer{
		Discovery: disc,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("receiver returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func generateSharedSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

type resolvedPeerOrigin struct {
	baseURL    string
	peerDomain string
}

func (h *Handler) resolvePeerOrigin(peerDomain string) resolvedPeerOrigin {
	if h.peerOrigin == nil {
		return resolvedPeerOrigin{}
	}
	decision := h.peerOrigin.Resolve(peerDomain)
	return resolvedPeerOrigin{
		baseURL:    decision.BaseURL,
		peerDomain: decision.PeerDomain,
	}
}
