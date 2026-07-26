package signature_test

import (
	"context"
	"testing"

	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
)

func TestGetPeerIdentity(t *testing.T) {
	// Without peer identity
	ctx := context.Background()

	pi := sig.GetPeerIdentity(ctx)
	if pi != nil {
		t.Error("expected nil peer identity for empty context")
	}

	// With peer identity
	ctx = context.WithValue(ctx, sig.PeerIdentityKey, &sig.PeerIdentity{
		Authority:           "example.com",
		AuthorityForCompare: "example.com",
		Authenticated:       true,
		KeyID:               "https://example.com#key1",
	})

	pi = sig.GetPeerIdentity(ctx)
	if pi == nil {
		t.Fatal("expected peer identity")
	}

	if pi.Authority != "example.com" {
		t.Errorf("expected authority 'example.com', got %q", pi.Authority)
	}

	if pi.AuthorityForCompare != "example.com" {
		t.Errorf("expected authority_for_compare 'example.com', got %q", pi.AuthorityForCompare)
	}

	if !pi.Authenticated {
		t.Error("expected authenticated=true")
	}
}
