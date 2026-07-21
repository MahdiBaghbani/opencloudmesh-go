package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// OCMProviderConfig holds OCM discovery configuration. The type and its input
// resolution live in the discovery/resolve helper; the service keeps these
// aliases so config decoding and tests continue to use service-local names.
type OCMProviderConfig = resolve.ProviderConfig

// APIVersionOverride applies a peer-profile-bound apiVersion override.
type APIVersionOverride = resolve.APIVersionOverride

type ocmHandler struct {
	data         *spec.Discovery
	overrides    []APIVersionOverride
	peerContract *peercompat.CompiledContract
	peerIdentity resolve.RequestPeerIdentity
	log          *slog.Logger
}

func newOCMHandler(
	c *OCMProviderConfig,
	rawOCMProvider map[string]any,
	in resolve.ResolveInputs,
	log *slog.Logger,
) (*ocmHandler, error) {
	log = logutil.NoopIfNil(log)

	built := resolve.Resolve(c, rawOCMProvider, in)
	disc := discovery.BuildDiscovery(built.Params, log)

	peerIdentity := in.PeerIdentity
	if peerIdentity == nil {
		peerIdentity = requestPeerIdentityFromContext
	}

	return &ocmHandler{
		data:         disc,
		overrides:    built.Overrides,
		peerContract: in.PeerContract,
		peerIdentity: peerIdentity,
		log:          log,
	}, nil
}

func requestPeerIdentityFromContext(r *http.Request) string {
	pi := inboundsignature.GetPeerIdentity(r.Context())
	if pi == nil {
		return ""
	}
	if peer := strings.TrimSpace(pi.AuthorityForCompare); peer != "" {
		return peer
	}
	return strings.TrimSpace(pi.Authority)
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := h.data

	if len(h.overrides) > 0 {
		peer := ""
		if h.peerIdentity != nil {
			peer = h.peerIdentity(r)
		}
		if version, ok := resolve.SelectAPIVersionOverride(
			h.overrides,
			h.peerContract,
			peer,
			r.Header.Get("User-Agent"),
		); ok {
			clone := *data
			clone.APIVersion = version
			data = &clone
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}
