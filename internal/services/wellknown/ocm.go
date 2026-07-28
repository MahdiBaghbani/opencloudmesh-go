package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type ocmHandler struct {
	data *spec.Discovery
}

func newOCMHandler(
	c *resolve.ProviderConfig,
	rawOCMProvider map[string]any,
	in resolve.ResolveInputs,
	log *slog.Logger,
) *ocmHandler {
	log = logutil.NoopIfNil(log)

	built := resolve.Resolve(c, rawOCMProvider, in)
	disc := discovery.BuildDiscovery(built.Params, log)

	return &ocmHandler{
		data: disc,
	}
}

func (h *ocmHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(h.data)
}
