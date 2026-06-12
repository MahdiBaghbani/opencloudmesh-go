package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// OCMProviderConfig holds OCM discovery configuration. The type and its input
// resolution live in the discovery/resolve helper; the service keeps these
// aliases so config decoding and tests continue to use service-local names.
type OCMProviderConfig = resolve.ProviderConfig

// APIVersionOverride allows overriding apiVersion based on User-Agent.
type APIVersionOverride = resolve.APIVersionOverride

type ocmHandler struct {
	data      *spec.Discovery
	overrides []APIVersionOverride
	log       *slog.Logger
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

	return &ocmHandler{data: disc, overrides: built.Overrides, log: log}, nil
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := h.data

	if len(h.overrides) > 0 {
		ua := r.Header.Get("User-Agent")
		for _, override := range h.overrides {
			if override.UserAgentContains != "" && strings.Contains(ua, override.UserAgentContains) {
				clone := *data
				clone.APIVersion = override.APIVersion
				data = &clone
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}
