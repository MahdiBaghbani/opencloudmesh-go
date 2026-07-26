package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestAccess_UnsetProtocolFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "token") {
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newExchangeAccessClient(t, srv)

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   srv.URL,
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Method: "GET",
	})
	if err == nil {
		t.Fatal("expected unset protocol to fail closed")
	}

	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

func TestAccess_NilDiscoveryFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	client := newExchangeAccessClient(t, srv)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Status:       "accepted",
			SenderHost:   "http://example.com",
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Protocol: "webdav",
		Method:   "GET",
	}, nil)
	if err == nil {
		t.Fatalf("expected nil discovery to fail closed, got mode %q", decision.Mode)
	}

	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonDiscoveryFailed {
		t.Errorf("expected discovery failed error, got: %v", err)
	}
}

func TestAccess_NilShareFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exchangeDiscoveryHandler(w, r, "token") {
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newExchangeAccessClient(t, srv)

	_, err := client.Access(context.Background(), AccessOptions{
		Share:    nil,
		Protocol: "webdav",
		Method:   "GET",
	})
	if err == nil {
		t.Fatal("expected nil share to fail closed")
	}

	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}
