// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestNewOCMHandler_TokenExchangePath(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	c.TokenExchange.Path = "exchange"
	raw := map[string]any{
		"token_exchange": map[string]any{"path": "exchange"},
	}

	h := newOCMHandler(
		c,
		raw,
		handlerResolveInputs(t, "/app"),
		testLogger(),
	)

	found := slices.Contains(h.data.Capabilities, "exchange-token")

	if !found {
		t.Error("expected 'exchange-token' in capabilities")
	}

	expected := "https://example.com/app/ocm/exchange"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_TokenExchangeDefaultPath(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}

	h := newOCMHandler(c, nil, handlerResolveInputs(t, ""), testLogger())

	expected := "https://example.com/ocm/token"
	if h.data.TokenEndPoint != expected {
		t.Errorf("expected tokenEndPoint %q, got %q", expected, h.data.TokenEndPoint)
	}
}

func TestNewOCMHandler_CodeFlowDrivesExchangeToken(t *testing.T) {
	t.Parallel()
	t.Run("non-nil code flow adds exchange-token", func(t *testing.T) {
		t.Parallel()

		c := &resolve.ProviderConfig{}
		c.TokenExchange.Path = "token"

		h := newOCMHandler(
			c,
			nil,
			handlerResolveInputs(t, ""),
			testLogger(),
		)

		found := slices.Contains(h.data.Capabilities, "exchange-token")

		if !found {
			t.Error("expected exchange-token in capabilities when code flow is configured")
		}

		if h.data.TokenEndPoint == "" {
			t.Error("expected non-empty tokenEndPoint")
		}
	})
}

func TestNewOCMHandler_CodeFlowDrivesTokenExchangeCriteria(t *testing.T) {
	t.Parallel()
	t.Run("RequiresTokenExchange=true adds token-exchange criteria", func(t *testing.T) {
		t.Parallel()

		c := &resolve.ProviderConfig{}
		c.TokenExchange.Path = "token"

		h := newOCMHandler(
			c,
			nil,
			handlerResolveInputs(t, ""),
			testLogger(),
		)

		if !h.data.HasCriteria(spec.CriteriaMustExchangeToken) {
			t.Error("expected must-exchange-token in criteria when code-flow RequiresTokenExchange=true")
		}
	})

	t.Run("empty criteria serializes as []", func(t *testing.T) {
		t.Parallel()

		c := &resolve.ProviderConfig{}

		h := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())

		data, err := json.Marshal(h.data)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		criteriaRaw, ok := parsed["criteria"]
		if !ok {
			t.Error("criteria key must be present in JSON")
		}

		criteriaSlice, ok := criteriaRaw.([]any)
		if !ok {
			t.Errorf("criteria must be an array, got %T", criteriaRaw)
		}

		if len(criteriaSlice) != 0 {
			t.Errorf("expected empty criteria array, got %v", criteriaSlice)
		}
	})

	t.Run("nil CodeFlow yields strict-off discovery", func(t *testing.T) {
		t.Parallel()

		c := &resolve.ProviderConfig{}
		in := handlerResolveInputs(t, "")
		in.CodeFlow = nil

		h := newOCMHandler(c, nil, in, testLogger())

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
