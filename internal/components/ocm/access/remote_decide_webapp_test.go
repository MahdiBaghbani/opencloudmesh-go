package access

import (
	"errors"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestDecideAccessAuth_NilShareFailsClosed(t *testing.T) {
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share:    nil,
		Protocol: "webdav",
	}, &spec.Discovery{})
	if err == nil {
		t.Fatalf("expected nil share to fail closed, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch error, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingFieldsFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for missing webapp fields, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingRequirementFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for missing must-exchange-token, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappMissingTargetIntersectionFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	client.SetWebappReceiveTargets([]string{"blank"})

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed for empty target intersection, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappNoLocalTargetsFailsClosed(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	// No local webapp receive targets configured.

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed when no local webapp targets are configured, got mode %q", decision.Mode)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonProtocolMismatch {
		t.Errorf("expected protocol mismatch, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappRequiresHTTPSigButNotCapable(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
		Criteria:      []string{spec.CriteriaMustUseHTTPSig},
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:      []string{spec.RequirementMustExchangeToken},
			WebappURI:         "http://example.com/webapp",
			WebappTargets:     []string{"files"},
			WebappPermissions: []string{"read"},
			SharedSecret:      "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err == nil {
		t.Fatalf("expected fail-closed when peer requires http-sig but is not capable, got mode %q", decision.Mode)
	}
	if decision.Mode != AccessModeFailClosed {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeFailClosed)
	}
	if decision.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusForbidden)
	}
	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Errorf("expected signature required, got: %v", err)
	}
}

func TestDecideAccessAuth_WebappCodeFlowSuccess(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "http://example.com/ocm",
		Capabilities:  []string{"exchange-token"},
		TokenEndPoint: "http://example.com/ocm/token",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)
	client.SetWebappReceiveTargets([]string{"files"})

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements:  []string{spec.RequirementMustExchangeToken},
			WebappURI:     "http://example.com/webapp",
			WebappTargets: []string{"files"},
			SharedSecret:  "secret",
		},
		Protocol: "webapp",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Mode != AccessModeWebappCodeFlow {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeWebappCodeFlow)
	}
	if decision.HTTPStatus != http.StatusOK {
		t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusOK)
	}
}
