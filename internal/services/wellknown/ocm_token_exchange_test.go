package wellknown

import (
	"encoding/json"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestNewOCMHandler_TokenExchangePath(t *testing.T) {
	c := &resolve.ProviderConfig{}
	c.TokenExchange.Path = "exchange"
	raw := map[string]any{
		"token_exchange": map[string]any{"path": "exchange"},
	}
	h, err := newOCMHandler(
		c,
		raw,
		handlerResolveInputs(t, "https://example.com", "/app"),
		testLogger(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'exchange-token' in capabilities")
	}

	expected := "https://example.com/app/ocm/exchange"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeDefaultPath(t *testing.T) {
	c := &resolve.ProviderConfig{}
	h, err := newOCMHandler(c, nil, handlerResolveInputs(t, "https://example.com", ""), testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/ocm/token"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_CodeFlowDrivesExchangeToken(t *testing.T) {
	t.Run("code-flow TokenExchangeCapable=true adds exchange-token", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		c.TokenExchange.Path = "token"
		h, err := newOCMHandler(
			c,
			nil,
			handlerResolveInputs(t, "https://example.com", ""),
			testLogger(),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected exchange-token in capabilities when code-flow TokenExchangeCapable=true")
		}
		if h.data.TokenEndPoint == "" {
			t.Error("expected non-empty tokenEndPoint")
		}
	})
}

func TestNewOCMHandler_CodeFlowDrivesTokenExchangeCriteria(t *testing.T) {
	t.Run("RequiresTokenExchange=true adds token-exchange criteria", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		c.TokenExchange.Path = "token"
		h, err := newOCMHandler(
			c,
			nil,
			handlerResolveInputs(t, "https://example.com", ""),
			testLogger(),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCriteria(spec.CriteriaMustExchangeToken) {
			t.Error("expected must-exchange-token in criteria when code-flow RequiresTokenExchange=true")
		}
	})

	t.Run("empty criteria serializes as []", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		data, err := json.Marshal(h.data)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		criteriaRaw, ok := parsed["criteria"]
		if !ok {
			t.Error("criteria key must be present in JSON")
		}
		criteriaSlice, ok := criteriaRaw.([]interface{})
		if !ok {
			t.Errorf("criteria must be an array, got %T", criteriaRaw)
		}
		if len(criteriaSlice) != 0 {
			t.Errorf("expected empty criteria array, got %v", criteriaSlice)
		}
	})

	t.Run("nil CodeFlow yields strict-off discovery", func(t *testing.T) {
		c := &resolve.ProviderConfig{}
		in := handlerResolveInputs(t, "https://example.com", "")
		in.CodeFlow = nil
		h, err := newOCMHandler(c, nil, in, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				t.Fatal("expected no exchange-token capability when CodeFlow is nil")
			}
		}
		if h.data.HasCriteria(spec.CriteriaMustExchangeToken) {
			t.Error("expected no must-exchange-token criteria when CodeFlow is nil")
		}
		if h.data.HasCriteria(spec.CriteriaMustUseHTTPSig) {
			t.Error("expected no must-use-http-sig criteria when CodeFlow is nil")
		}
		if h.data.TokenEndPoint != "" {
			t.Error("expected empty tokenEndPoint when CodeFlow is nil (strict-off)")
		}
	})
}
