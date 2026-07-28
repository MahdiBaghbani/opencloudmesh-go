package wellknown

import (
	"encoding/json"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

type jwksHandler struct {
	keyManager *crypto.KeyManager
}

func newJWKSHandler(keyManager *crypto.KeyManager) http.Handler {
	return &jwksHandler{keyManager: keyManager}
}

func (h *jwksHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	if h.keyManager == nil {
		http.Error(w, "signing keys unavailable", http.StatusServiceUnavailable)
		return
	}

	set := h.keyManager.JWKS()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(set)
}
