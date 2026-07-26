package ocm

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Shares, invite-accepted, and token routes require a declared peer (HTTP 400
// when missing).
func TestService_AndPeerRoutesRejectMissingDeclaredPeer(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name        string
		path        string
		contentType string
		body        string
	}{
		{
			name:        "shares",
			path:        "/shares",
			contentType: "application/json",
			body:        `{}`,
		},
		{
			name:        "invite-accepted",
			path:        "/invite-accepted",
			contentType: "application/json",
			body:        `{"token":"invite-token","userID":"user-1"}`,
		},
		{
			name:        "token",
			path:        "/token",
			contentType: "application/x-www-form-urlencoded",
			body:        "grant_type=authorization_code&code=secret-code",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", tc.contentType)

			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 declared-peer fail-closed on %s (AndPeer wiring), got %d: %s",
					tc.name, w.Code, w.Body.String())
			}

			body := w.Body.String()
			if !strings.Contains(body, "declared peer") && !strings.Contains(body, "invalid declared peer") {
				t.Fatalf("%s body = %q, want declared-peer error", tc.name, body)
			}
		})
	}
}
