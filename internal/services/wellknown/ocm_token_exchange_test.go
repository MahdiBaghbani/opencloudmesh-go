package wellknown

import (
	"encoding/json"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

func TestNewOCMHandler_TokenExchangeDisabled(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	c.TokenExchange.Enabled = false
	d := &deps.Deps{}

	h, err := newOCMHandler(c, nil, d, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token exchange should NOT be in capabilities
	for _, cap := range h.data.Capabilities {
		if cap == "exchange-token" {
			t.Error("expected 'exchange-token' to NOT be in capabilities when disabled")
		}
	}

	// tokenEndPoint should be empty
	if h.data.TokenEndPoint != "" {
		t.Errorf("expected empty tokenEndPoint, got %q", h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeEnabled(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com/app",
	}
	c.TokenExchange.Enabled = true
	c.TokenExchange.Path = "exchange"
	d := &deps.Deps{}

	h, err := newOCMHandler(c, nil, d, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Token exchange should be in capabilities
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

	// tokenEndPoint should be set
	expected := "https://example.com/app/ocm/exchange"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeDefaultPath(t *testing.T) {
	c := &OCMProviderConfig{
		Endpoint: "https://example.com",
	}
	c.TokenExchange.Enabled = true
	// Path is empty; handler code falls back to "token"
	d := &deps.Deps{}

	h, err := newOCMHandler(c, nil, d, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "https://example.com/ocm/token"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_EvaluatorDrivesExchangeToken(t *testing.T) {
	t.Run("evaluator TokenExchangeCapable=true adds exchange-token", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Enabled = true
		c.TokenExchange.Path = "token"
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
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
			t.Error("expected exchange-token in capabilities when evaluator TokenExchangeCapable=true")
		}
		if h.data.TokenEndPoint == "" {
			t.Error("expected non-empty tokenEndPoint")
		}
	})

	t.Run("evaluator TokenExchangeCapable=false omits exchange-token", func(t *testing.T) {
		tokenExchangeEnabled := false
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Enabled = false
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				t.Error("expected exchange-token NOT in capabilities when evaluator TokenExchangeCapable=false")
			}
		}
		if h.data.TokenEndPoint != "" {
			t.Errorf("expected empty tokenEndPoint, got %q", h.data.TokenEndPoint)
		}
	})
}

func TestNewOCMHandler_EvaluatorDrivesTokenExchangeCriteria(t *testing.T) {
	t.Run("RequiresTokenExchange=true adds token-exchange criteria", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Enabled = true
		c.TokenExchange.Path = "token"
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, crit := range h.data.Criteria {
			if crit == "token-exchange" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected token-exchange in criteria when evaluator RequiresTokenExchange=true")
		}
	})

	t.Run("RequiresTokenExchange=false omits token-exchange criteria", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		c.TokenExchange.Enabled = true
		c.TokenExchange.Path = "token"
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, crit := range h.data.Criteria {
			if crit == "token-exchange" {
				t.Error("expected token-exchange NOT in criteria when evaluator RequiresTokenExchange=false")
			}
		}
	})

	t.Run("empty criteria serializes as []", func(t *testing.T) {
		tokenExchangeEnabled := false
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
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

	t.Run("per-service token_exchange override keeps evaluator strictness", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}
		raw := map[string]any{
			"token_exchange": map[string]any{
				"enabled": true,
			},
		}

		h, err := newOCMHandler(c, raw, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, crit := range h.data.Criteria {
			if crit == "token-exchange" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected token-exchange criteria to follow evaluator strictness even with per-service override")
		}
	})

	t.Run("never emit token-exchange criteria without capability", func(t *testing.T) {
		tokenExchangeEnabled := false
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: true,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				t.Fatal("did not expect exchange-token capability when code flow is disabled")
			}
		}
		if h.data.TokenEndPoint != "" {
			t.Fatalf("expected empty tokenEndPoint when code flow is disabled, got %q", h.data.TokenEndPoint)
		}
		for _, crit := range h.data.Criteria {
			if crit == "token-exchange" {
				t.Fatal("did not expect token-exchange criteria without exchange-token capability")
			}
		}
	})

	t.Run("per-service override cannot diverge evaluator capability", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: false,
			PeerPolicy:           "legacy",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		d := &deps.Deps{
			Config:              cfg,
			OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		}
		raw := map[string]any{
			"token_exchange": map[string]any{
				"enabled": false,
			},
		}

		h, err := newOCMHandler(c, raw, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		foundCapability := false
		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				foundCapability = true
				break
			}
		}
		if !foundCapability {
			t.Fatal("expected exchange-token capability to follow evaluator despite per-service override")
		}
		if h.data.TokenEndPoint == "" {
			t.Fatal("expected tokenEndPoint to be present when exchange-token is advertised")
		}
	})

	t.Run("raw config alone does not backfill capability", func(t *testing.T) {
		tokenExchangeEnabled := true
		cfg := &config.Config{
			PublicOrigin:         "https://example.com",
			TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
			RequireTokenExchange: true,
			PeerPolicy:           "strict",
		}
		c := &OCMProviderConfig{Endpoint: "https://example.com"}
		d := &deps.Deps{
			Config: cfg,
		}

		h, err := newOCMHandler(c, nil, d, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, cap := range h.data.Capabilities {
			if cap == "exchange-token" {
				t.Fatal("did not expect exchange-token capability without canonical policy")
			}
		}
		if h.data.TokenEndPoint != "" {
			t.Fatalf("expected empty tokenEndPoint without canonical policy, got %q", h.data.TokenEndPoint)
		}
	})
}
