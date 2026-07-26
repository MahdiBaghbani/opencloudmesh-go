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

func TestDecideAccessAuth_WebDAVTokenExchange(t *testing.T) {
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
		Protocol: "webdav",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Mode != AccessModeTokenExchange {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeTokenExchange)
	}
}

func TestDecideAccessAuth_WebDAVSharedSecret(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://example.com/ocm",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	decision, err := client.DecideAccessAuth(AccessOptions{
		Share:    &ShareInfo{},
		Protocol: "webdav",
	}, disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Mode != AccessModeSharedSecret {
		t.Errorf("mode = %q, want %q", decision.Mode, AccessModeSharedSecret)
	}
}

func TestDecideAccessAuth_WebDAVRequiresButNotCapable(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "http://example.com/ocm",
	}
	client := NewClient(nil, &discovery.Client{}, nil, nil)

	_, err := client.DecideAccessAuth(AccessOptions{
		Share: &ShareInfo{
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
	}, disc)
	if err == nil {
		t.Fatal("expected fail-closed when token exchange required but peer not capable")
	}

	var ce *reason.ClassifiedError
	if !errors.As(err, &ce) || ce.ReasonCode != reason.ReasonPeerCapabilityMissing {
		t.Errorf("expected peer capability missing, got: %v", err)
	}
}

func TestDecideAccessAuth_WebDAVRequiresHTTPSigButNotCapable(t *testing.T) {
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
			Requirements: []string{spec.RequirementMustExchangeToken},
		},
		Protocol: "webdav",
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

// SharedSecret bearer access is unsigned per the OCM spec; must-use-http-sig
// governs OCM API requests such as the token POST, not bearer WebDAV resource
// access; therefore this branch does not fail closed on signature policy.
func TestDecideAccessAuth_WebDAVSharedSecret_IgnoresMustUseHTTPSig(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
	}{
		{
			name:         "advertises http-sig and capable",
			capabilities: []string{"http-sig"},
		},
		{
			name:         "advertises must-use-http-sig but not capable",
			capabilities: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disc := &spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     "http://example.com/ocm",
				Capabilities: tt.capabilities,
				Criteria:     []string{spec.CriteriaMustUseHTTPSig},
			}
			client := NewClient(nil, &discovery.Client{}, nil, nil)

			decision, err := client.DecideAccessAuth(AccessOptions{
				Share:    &ShareInfo{},
				Protocol: "webdav",
			}, disc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Mode != AccessModeSharedSecret {
				t.Errorf("mode = %q, want %q", decision.Mode, AccessModeSharedSecret)
			}

			if decision.HTTPStatus != http.StatusOK {
				t.Errorf("HTTPStatus = %d, want %d", decision.HTTPStatus, http.StatusOK)
			}
		})
	}
}

func TestDecideAccessAuth_WebDAVOptionalExchange(t *testing.T) {
	tests := []struct {
		name          string
		requirements  []string
		capabilities  []string
		tokenEndPoint string
		criteria      []string
		wantMode      string
		wantErr       bool
	}{
		{
			name:          "optional requirement omitted and peer capable",
			capabilities:  []string{spec.CapabilityExchangeToken},
			tokenEndPoint: "http://example.com/ocm/token",
			wantMode:      AccessModeExchangeThenFallback,
		},
		{
			name:         "optional requirement omitted and peer incapable",
			capabilities: []string{},
			wantMode:     AccessModeSharedSecret,
		},
		{
			name:          "must-exchange-token present and peer capable",
			requirements:  []string{spec.RequirementMustExchangeToken},
			capabilities:  []string{spec.CapabilityExchangeToken},
			tokenEndPoint: "http://example.com/ocm/token",
			wantMode:      AccessModeTokenExchange,
		},
		{
			name:         "must-exchange-token present and peer incapable",
			requirements: []string{spec.RequirementMustExchangeToken},
			capabilities: []string{},
			wantMode:     AccessModeFailClosed,
			wantErr:      true,
		},
		{
			name:          "optional omitted capable peer with unfulfilled signature policy",
			capabilities:  []string{spec.CapabilityExchangeToken},
			tokenEndPoint: "http://example.com/ocm/token",
			criteria:      []string{spec.CriteriaMustUseHTTPSig},
			wantMode:      AccessModeExchangeThenFallback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disc := &spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      "http://example.com/ocm",
				Capabilities:  tt.capabilities,
				TokenEndPoint: tt.tokenEndPoint,
				Criteria:      tt.criteria,
			}
			client := NewClient(nil, &discovery.Client{}, nil, nil)

			decision, err := client.DecideAccessAuth(AccessOptions{
				Share: &ShareInfo{
					Requirements: tt.requirements,
				},
				Protocol: "webdav",
			}, disc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}

			if decision.Mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", decision.Mode, tt.wantMode)
			}
		})
	}
}
