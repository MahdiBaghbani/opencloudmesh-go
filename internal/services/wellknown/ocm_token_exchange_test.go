package wellknown

import (
	"encoding/json"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestNewOCMHandler_TokenExchangePath(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com/app",
	}
	c.TokenExchange.Path = "exchange"
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{CodeFlow: policy.NewCodeFlow()}, testLogger())
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
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	h, err := newOCMHandler(c, nil, resolve.ResolveInputs{CodeFlow: policy.NewCodeFlow()}, testLogger())
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
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Path = "token"
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{CodeFlow: policy.NewCodeFlow()}, testLogger())
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
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Path = "token"
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{CodeFlow: policy.NewCodeFlow()}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !h.data.HasCriteria(spec.CriteriaMustExchangeToken) {
			t.Error("expected must-exchange-token in criteria when code-flow RequiresTokenExchange=true")
		}
	})

	t.Run("empty criteria serializes as []", func(t *testing.T) {
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
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

	t.Run("raw config alone does not backfill capability", func(t *testing.T) {
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		h, err := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				t.Fatal("did not expect exchange-token capability without a code-flow policy")
			}
		}
		if h.data.TokenEndPoint != "" {
			t.Fatalf("expected empty tokenEndPoint without a code-flow policy, got %q", h.data.TokenEndPoint)
		}
	})
}
