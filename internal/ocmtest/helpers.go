// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package ocmtest provides test helpers for OCM component tests.
// All functions are intended for use from _test.go files only.
package ocmtest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	ocmpolicy "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// SilentLogger returns a logger that discards all output.
// Use in tests that require a non-nil logger but don't need log output.
func SilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// MustAllowHTTPContract builds a CompiledContract that permits plain HTTP for
// all peers via a wildcard mapping. Use in handler tests that talk to local
// httptest servers over HTTP.
func MustAllowHTTPContract(t *testing.T) *peercompat.CompiledContract {
	t.Helper()
	return MustCompileContract(t,
		map[string]*peercompat.Profile{
			"allow-http-test": {
				Name:      "allow-http-test",
				AllowHTTP: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*", ProfileName: "allow-http-test"},
		},
	)
}

// MustCompileContract builds a CompiledContract from profiles and mappings.
// Calls t.Fatal if compilation fails.
func MustCompileContract(
	t *testing.T,
	profiles map[string]*peercompat.Profile,
	mappings []peercompat.ProfileMapping,
) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.NewCompiledContract(profiles, mappings)
	if err != nil {
		t.Fatalf("MustCompileContract: %v", err)
	}
	return contract
}

// MustCompileFromRegistry builds a CompiledContract from a ProfileRegistry.
// Calls t.Fatal if compilation fails.
func MustCompileFromRegistry(
	t *testing.T,
	registry *peercompat.ProfileRegistry,
) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("MustCompileFromRegistry: %v", err)
	}
	return contract
}

// RuntimePolicy builds a RuntimePolicy from cfg and contract.
func RuntimePolicy(
	t *testing.T,
	cfg *config.Config,
	contract *peercompat.CompiledContract,
) *ocmpolicy.RuntimePolicy {
	t.Helper()
	return ocmpolicy.NewRuntimePolicy(cfg, contract)
}

// OutboundPolicy builds an OutboundPolicy by resolving inputs from the runtime
// and canonical OCM policy, then constructing via outboundsigning.NewOutboundPolicy.
func OutboundPolicy(
	t *testing.T,
	runtime *ocmpolicy.RuntimePolicy,
	openCloudMesh *ocmpolicy.OpenCloudMeshPolicy,
	contract *peercompat.CompiledContract,
) *outboundsigning.OutboundPolicy {
	t.Helper()
	return outboundsigning.NewOutboundPolicy(
		outboundsigning.ResolveInputs(runtime, openCloudMesh),
		contract,
	)
}
