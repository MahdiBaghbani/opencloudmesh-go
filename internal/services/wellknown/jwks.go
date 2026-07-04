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

func (h *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.keyManager == nil {
		http.Error(w, "signing keys unavailable", http.StatusServiceUnavailable)
		return
	}

	set := h.keyManager.JWKS()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(set)
}
