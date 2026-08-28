// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func matchingShareFixture() (*IncomingShare, *spec.NewShareRequest) {
	expiration := int64(1700000000)

	existing := &IncomingShare{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		ProtocolName: "webdav",
		Description:  "notes",
		Expiration:   &expiration,
		WebDAVID:     "abc123",
		SharedSecret: "secret123",
		Permissions:  []string{"read", "write"},
		Requirements: []string{"must-exchange-token", "must-use-mfa"},
	}

	req := &spec.NewShareRequest{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		Description:  "notes",
		Expiration:   &expiration,
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          "abc123",
				SharedSecret: "secret123",
				Permissions:  []string{"read", "write"},
				Requirements: []string{"must-exchange-token", "must-use-mfa"},
			},
		},
	}

	return existing, req
}

func TestIncomingShareMatchesRequest(t *testing.T) {
	t.Parallel()

	existing, req := matchingShareFixture()

	if !incomingShareMatchesRequest(existing, req) {
		t.Fatal("expected matching payload")
	}

	req.Protocol.WebDAV.URI = "different"
	if incomingShareMatchesRequest(existing, req) {
		t.Fatal("expected mismatch on uri")
	}
}

func TestIncomingShareMatchesRequest_NilWebDAV(t *testing.T) {
	t.Parallel()

	existing := &IncomingShare{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		ProtocolName: "webdav",
	}

	req := &spec.NewShareRequest{
		Name:         "test.txt",
		ResourceType: "file",
		ShareWith:    "alice@localhost:9200",
		ShareType:    "user",
		Owner:        "owner@sender.com",
		Sender:       "sender@sender.com",
		Protocol: spec.Protocol{
			Name: "webdav",
		},
	}

	if !incomingShareMatchesRequest(existing, req) {
		t.Fatal("expected nil webdav request to match empty stored webdav material")
	}
}

func TestIncomingShareMatchesRequest_FieldMismatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(existing *IncomingShare, req *spec.NewShareRequest)
	}{
		{
			name: "requirements",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.Protocol.WebDAV.Requirements = []string{"other-requirement"}
			},
		},
		{
			name: "expiration",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				other := int64(1800000000)
				req.Expiration = &other
			},
		},
		{
			name: "description",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.Description = "changed description"
			},
		},
		{
			name: "owner",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.Owner = "other@sender.com"
			},
		},
		{
			name: "sender",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.Sender = "other-sender@sender.com"
			},
		},
		{
			name: "protocol name",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.Protocol.Name = "multi"
			},
		},
		{
			name: "share type",
			mutate: func(_ *IncomingShare, req *spec.NewShareRequest) {
				req.ShareType = "group"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			existing, req := matchingShareFixture()
			tc.mutate(existing, req)

			if incomingShareMatchesRequest(existing, req) {
				t.Fatal("expected field mismatch")
			}
		})
	}
}

func TestIncomingShareMatchesRequest_OrderSensitiveSlices(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(req *spec.NewShareRequest)
	}{
		{
			name: "permissions-reordered",
			mutate: func(req *spec.NewShareRequest) {
				req.Protocol.WebDAV.Permissions = []string{"write", "read"}
			},
		},
		{
			name: "requirements-reordered",
			mutate: func(req *spec.NewShareRequest) {
				req.Protocol.WebDAV.Requirements = []string{"must-use-mfa", "must-exchange-token"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			existing, req := matchingShareFixture()
			tc.mutate(req)

			if incomingShareMatchesRequest(existing, req) {
				t.Fatal("expected reordered slice to mismatch")
			}
		})
	}
}

func TestHandleExistingIncomingShare_ReorderedSlicesReturns409(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(req *spec.NewShareRequest)
	}{
		{
			name: "permissions-reordered",
			mutate: func(req *spec.NewShareRequest) {
				req.Protocol.WebDAV.Permissions = []string{"write", "read"}
			},
		},
		{
			name: "requirements-reordered",
			mutate: func(req *spec.NewShareRequest) {
				req.Protocol.WebDAV.Requirements = []string{"must-use-mfa", "must-exchange-token"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			existing, req := matchingShareFixture()
			tc.mutate(req)

			w := httptest.NewRecorder()
			log := slog.Default()
			resolvedUser := &identity.User{DisplayName: "Alice A"}

			if !handleExistingIncomingShare(t.Context(), w, log, existing, req, "sender.com", resolvedUser, nil) {
				t.Fatal("expected existing share to be handled")
			}

			if w.Code != http.StatusConflict {
				t.Fatalf("expected 409, got %d", w.Code)
			}
		})
	}
}

func TestOrderedStringSlicesEqual(t *testing.T) {
	t.Parallel()

	if !orderedStringSlicesEqual(nil, nil) {
		t.Fatal("expected nil slices to compare equal")
	}

	if !orderedStringSlicesEqual([]string{}, nil) {
		t.Fatal("expected empty and nil slices to compare equal")
	}

	if orderedStringSlicesEqual([]string{"read"}, []string{"write"}) {
		t.Fatal("expected different slices to mismatch")
	}

	if orderedStringSlicesEqual([]string{"read", "write"}, []string{"read"}) {
		t.Fatal("expected different lengths to mismatch")
	}

	if orderedStringSlicesEqual([]string{"read", "write"}, []string{"write", "read"}) {
		t.Fatal("expected reordered slices to mismatch")
	}
}
