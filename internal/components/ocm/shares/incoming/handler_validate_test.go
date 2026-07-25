package incoming_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestValidateRequiredFields_AllMissing(t *testing.T) {
	req := &spec.NewShareRequest{}
	errs := spec.ValidateRequiredFields(req)

	if len(errs) == 0 {
		t.Fatal("expected validation errors for empty request")
	}

	names := map[string]bool{}
	for _, e := range errs {
		names[e.Name] = true
		if e.Message != "REQUIRED" {
			t.Errorf("expected message REQUIRED for field %s, got %s", e.Name, e.Message)
		}
	}

	required := []string{"shareWith", "name", "providerId", "owner", "sender", "shareType", "resourceType", "protocol"}
	for _, f := range required {
		if !names[f] {
			t.Errorf("expected validation error for field %s", f)
		}
	}
}

func TestValidateRequiredFields_AllPresent(t *testing.T) {
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{Name: "webdav", WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors, got %d", len(errs))
	}
}

func TestValidateRequiredFields_ProtocolWithOnlyWebDAV(t *testing.T) {
	// Protocol has WebDAV but no name -- should not trigger "protocol REQUIRED"
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors for protocol with webdav, got %d: %v", len(errs), errs)
	}
}
