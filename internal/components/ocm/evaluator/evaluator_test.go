package evaluator_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/evaluator"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func ptrBool(b bool) *bool { return &b }

func TestEvaluate_AllEnabled(t *testing.T) {
	cfg := &config.Config{
		TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(true)},
		WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "strict"},
		NonStrictPeerOutboundPolicy: "prefer-strict",
	}
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if !eval.CodeFlowCapability {
		t.Error("expected CodeFlowCapability true")
	}
	if !eval.ReceiverStrictness {
		t.Error("expected ReceiverStrictness true")
	}
	if eval.NonStrictPeerOutboundPolicy != "prefer-strict" {
		t.Errorf("expected NonStrictPeerOutboundPolicy prefer-strict, got %q", eval.NonStrictPeerOutboundPolicy)
	}
}

func TestEvaluate_AllDefaults(t *testing.T) {
	cfg := config.DevConfig()
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if !eval.CodeFlowCapability {
		t.Error("expected CodeFlowCapability true in dev (token exchange enabled by default)")
	}
	if eval.ReceiverStrictness {
		t.Error("expected ReceiverStrictness false in dev (lenient mode)")
	}
	if eval.NonStrictPeerOutboundPolicy != "legacy-compatible" {
		t.Errorf("expected NonStrictPeerOutboundPolicy legacy-compatible, got %q", eval.NonStrictPeerOutboundPolicy)
	}
}

func TestEvaluate_TokenExchangeDisabled(t *testing.T) {
	cfg := &config.Config{
		TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(false)},
		WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "off"},
		NonStrictPeerOutboundPolicy: "legacy-compatible",
	}
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if eval.CodeFlowCapability {
		t.Error("expected CodeFlowCapability false when token exchange disabled")
	}
	if eval.ReceiverStrictness {
		t.Error("expected ReceiverStrictness false when mode=off")
	}
}

func TestEvaluate_LenientModeNotStrict(t *testing.T) {
	cfg := &config.Config{
		TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(true)},
		WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "lenient"},
		NonStrictPeerOutboundPolicy: "legacy-compatible",
	}
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if !eval.CodeFlowCapability {
		t.Error("expected CodeFlowCapability true")
	}
	if eval.ReceiverStrictness {
		t.Error("expected ReceiverStrictness false for lenient mode")
	}
}

func TestEvaluate_FailFastPolicy(t *testing.T) {
	cfg := &config.Config{
		TokenExchange:               config.TokenExchangeConfig{Enabled: ptrBool(true)},
		WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "strict"},
		NonStrictPeerOutboundPolicy: "fail-fast",
	}
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if eval.NonStrictPeerOutboundPolicy != "fail-fast" {
		t.Errorf("expected NonStrictPeerOutboundPolicy fail-fast, got %q", eval.NonStrictPeerOutboundPolicy)
	}
}

func TestEvaluate_NilTokenExchangeEnabled(t *testing.T) {
	cfg := &config.Config{
		WebDAVTokenExchange:         config.WebDAVTokenExchangeConfig{Mode: "off"},
		NonStrictPeerOutboundPolicy: "legacy-compatible",
	}
	eval := evaluator.NewLocalEvaluator(cfg).Evaluate()

	if eval.CodeFlowCapability {
		t.Error("expected CodeFlowCapability false when TokenExchange.Enabled is nil")
	}
}
