package access

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// TestDecideAccessAuth_WebappProtocolFailsClosed guards remote.go:131.
// WebDAV is the only supported receive protocol; ProtocolWebapp must be
// rejected explicitly with ReasonProtocolMismatch before any discovery work.
func TestDecideAccessAuth_WebappProtocolFailsClosed(t *testing.T) {
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share:    &ShareInfo{},
		Protocol: ProtocolWebapp,
	}, &spec.Discovery{})
	if err == nil {
		t.Fatalf("expected webapp protocol to fail closed, got mode %q", decision.Mode)
	}
	if decision.Mode != AccessModeFailClosed {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeFailClosed)
	}
	if decision.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusForbidden)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

// TestAccess_WebappProtocolFailsClosed guards remote.go:206.
// Access must reject ProtocolWebapp before performing discovery or token
// exchange; webapp is not a supported receive path on the access plane.
func TestAccess_WebappProtocolFailsClosed(t *testing.T) {
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	_, err := client.Access(context.Background(), AccessOptions{
		Share: &ShareInfo{
			Status:       ShareStatusAccepted,
			SenderHost:   "http://example.com",
			SharedSecret: "secret",
			WebDAVID:     "file-id",
		},
		Protocol: ProtocolWebapp,
		Method:   http.MethodGet,
	})
	if err == nil {
		t.Fatal("expected webapp protocol to fail closed")
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}
