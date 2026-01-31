package shares_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const testProvider = "example.com"

func testCurrentUser(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return user, nil
	}
}

func failCurrentUser() func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return nil, http.ErrNoCookie
	}
}

func newTestHandler(currentUser func(context.Context) (*identity.User, error)) *outgoingshares.Handler {
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()

	return outgoingshares.NewHandler(
		repo, nil, nil, nil, nil,
		cfg,
		testProvider,
		currentUser,
		testLogger,
	)
}

func TestHandleCreate_Unauthenticated_Returns401(t *testing.T) {
	handler := newTestHandler(failCurrentUser())

	body := `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_MissingFields(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	tests := []struct {
		name string
		body string
	}{
		{"missing receiverDomain", `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing shareWith", `{"receiverDomain":"example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing localPath", `{"receiverDomain":"example.com","shareWith":"user@example.com","permissions":["read"]}`},
		{"missing permissions", `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleCreate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleCreate_FileNotFound(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))
	handler.SetAllowedPaths([]string{"/tmp"})

	body := `{
		"receiverDomain": "example.com",
		"shareWith": "user@example.com",
		"localPath": "/tmp/nonexistent-file-12345.txt",
		"permissions": ["read"]
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_OwnerSenderUseBase64UserID(t *testing.T) {
	// Verify the handler stores owner/sender with base64-encoded user ID format
	// (not hardcoded placeholders). We test by creating a share with a real file
	// but without a discovery client, so the share is stored but sending fails.
	// We then check the stored share's owner/sender fields.

	user := &identity.User{ID: "user-uuid-123", Username: "alice", Email: "alice@example.org"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()

	handler := outgoingshares.NewHandler(
		repo, nil, nil, nil, nil,
		cfg,
		testProvider,
		testCurrentUser(user),
		testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	// Create a temporary file for sharing
	tmpFile, err := os.CreateTemp("/tmp", "outgoing-share-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	body := `{
		"receiverDomain": "receiver.example.com",
		"shareWith": "bob@receiver.example.com",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// The handler returns 500 (nil discovery client), but the share is stored first.
	// Check the stored share to verify owner/sender format.
	if w.Code != http.StatusInternalServerError {
		t.Logf("unexpected status %d (expected 500 from nil discovery client): %s", w.Code, w.Body.String())
	}

	allShares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}

	if len(allShares) == 0 {
		t.Fatal("expected at least one share to be stored before discovery failure")
	}

	share := allShares[0]

	// Verify owner uses base64-encoded user ID format
	expectedB64 := base64.StdEncoding.EncodeToString([]byte("user-uuid-123"))
	expectedOwner := expectedB64 + "@" + testProvider
	if share.Owner != expectedOwner {
		t.Errorf("owner = %q, want %q (base64 user ID format)", share.Owner, expectedOwner)
	}
	if share.Sender != expectedOwner {
		t.Errorf("sender = %q, want %q (base64 user ID format)", share.Sender, expectedOwner)
	}
}

func TestHandleCreate_MethodNotAllowed(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	req := httptest.NewRequest(http.MethodGet, "/api/shares/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCreate_ErrorResponseUsesAPIEnvelope(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	body := `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// Should be 400 (missing receiverDomain)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Verify the response uses api error envelope (has error.reason_code)
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"]
	if !ok {
		t.Fatal("error response missing 'error' field (should use api error envelope)")
	}
	errMap, ok := errObj.(map[string]interface{})
	if !ok {
		t.Fatal("error field is not an object")
	}
	if _, ok := errMap["reason_code"]; !ok {
		t.Error("error response missing reason_code field (should use api error envelope)")
	}
}
