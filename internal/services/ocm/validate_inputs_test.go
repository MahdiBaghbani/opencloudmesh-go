package ocm

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestValidateInputs_ReportsMissingRuntimePolicy(t *testing.T) {
	cfg := config.DevConfig()
	in := testInputs(cfg)
	in.RuntimePolicy = nil

	err := validateInputs(in)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "RuntimePolicy is required") {
		t.Fatalf("error = %q, want RuntimePolicy required", err.Error())
	}
}

func TestValidateInputs_AcceptsRuntimePolicy(t *testing.T) {
	cfg := config.DevConfig()
	in := Inputs{
		RuntimePolicy: policy.NewRuntimePolicy(cfg, nil),
	}

	if err := validateInputs(in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
