package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// OCMProviderConfig holds OCM discovery configuration. The type and its input
// resolution live in the discovery/resolve helper; the service keeps these
// aliases so config decoding and tests continue to use service-local names.
type OCMProviderConfig = resolve.ProviderConfig

// APIVersionOverride allows overriding apiVersion based on User-Agent.
type APIVersionOverride = resolve.APIVersionOverride

type ocmHandler struct {
	data      *spec.Discovery      // static, computed once at init
	overrides []APIVersionOverride // User-Agent based apiVersion overrides
	log       *slog.Logger
}

// newOCMHandler builds the static OCM discovery handler. Input resolution
// (config defaulting plus cross-cutting derivation from SharedDeps) is handled
// by the discovery/resolve helper; this wires the resolved params to the
// discovery builder and the HTTP handler wrapper.
//
// rawOCMProvider is the raw config map from TOML (used for key-presence
// detection so we can distinguish "not set" from "explicitly set to zero").
func newOCMHandler(c *OCMProviderConfig, rawOCMProvider map[string]any, d *deps.Deps, log *slog.Logger) (*ocmHandler, error) {
	log = logutil.NoopIfNil(log)

	in := resolve.Resolve(c, rawOCMProvider, d, log)
	disc := discovery.BuildDiscovery(in.Params, log)

	return &ocmHandler{data: disc, overrides: in.Overrides, log: log}, nil
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := h.data

	// Check for User-Agent based apiVersion override (Nextcloud crawler compatibility)
	if len(h.overrides) > 0 {
		ua := r.Header.Get("User-Agent")
		for _, override := range h.overrides {
			if override.UserAgentContains != "" && strings.Contains(ua, override.UserAgentContains) {
				// Clone and override apiVersion
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
