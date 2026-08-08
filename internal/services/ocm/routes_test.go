// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()

	specs := registeredRouteSpecs(opts)
	if len(specs) != 4 {
		t.Fatalf("expected 4 route specs, got %d", len(specs))
	}

	for i := range specs {
		spec := specs[i]
		if spec.Method == http.MethodGet {
			continue
		}

		if spec.SurfaceClass != service.SurfaceProtocol {
			t.Errorf("spec %q surface = %q, want protocol", spec.ID, spec.SurfaceClass)
		}

		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}

		if spec.TrustClass != service.TrustPeerRequired {
			t.Errorf("spec %q trust = %q, want %q", spec.ID, spec.TrustClass, service.TrustPeerRequired)
		}

		if spec.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("spec %q handler auth = %q, want %q", spec.ID, spec.HandlerAuth, service.HandlerAuthRequiredHTTPSig)
		}
	}
}

// TestRegisteredRouteSpecs_JWKSDiscoveryRoute confirms the local JWKS route is
// registered as a public, unauthenticated GET discovery route alongside the
// existing protocol specs, and that it advertises the "jwks" discovery field.
func TestRegisteredRouteSpecs_JWKSDiscoveryRoute(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()

	specs := registeredRouteSpecs(opts)

	var jwksSpec *service.RouteSpec

	for i := range specs {
		if specs[i].ID == "ocm-jwks" {
			jwksSpec = &specs[i]

			break
		}
	}

	if jwksSpec == nil {
		t.Fatal("expected ocm-jwks route spec")
	}

	if jwksSpec.Method != http.MethodGet {
		t.Errorf("jwks spec method = %q, want GET", jwksSpec.Method)
	}

	if jwksSpec.Pattern != RouteJWKS {
		t.Errorf("jwks spec pattern = %q, want %q", jwksSpec.Pattern, RouteJWKS)
	}

	if jwksSpec.SessionPolicy != service.SessionPublic {
		t.Errorf("jwks spec session = %q, want public", jwksSpec.SessionPolicy)
	}

	if jwksSpec.HandlerAuth != service.HandlerAuthNone {
		t.Errorf("jwks spec handler auth = %q, want none", jwksSpec.HandlerAuth)
	}

	if jwksSpec.SurfaceClass != service.SurfaceDiscovery {
		t.Errorf("jwks spec surface = %q, want discovery", jwksSpec.SurfaceClass)
	}

	if jwksSpec.TrustClass != service.TrustPeerNone {
		t.Errorf("jwks spec trust = %q, want peer-trust-none", jwksSpec.TrustClass)
	}

	if len(jwksSpec.DiscoveryFields) != 1 || jwksSpec.DiscoveryFields[0] != "jwks" {
		t.Errorf("jwks spec discovery fields = %v, want [jwks]", jwksSpec.DiscoveryFields)
	}
}

func TestRegisteredRouteSpecs_ProtocolPostInvariants(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()

	var postRows []service.RouteSpec

	for _, spec := range registeredRouteSpecs(opts) {
		if spec.Service != "ocm" || spec.Method != http.MethodPost ||
			spec.SurfaceClass != service.SurfaceProtocol {
			continue
		}

		postRows = append(postRows, spec)
	}

	if len(postRows) != 3 {
		t.Fatalf("expected 3 OCM POST protocol route specs, got %d", len(postRows))
	}

	for _, spec := range postRows {
		if spec.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("spec %q handler auth = %q, want %q",
				spec.ID, spec.HandlerAuth, service.HandlerAuthRequiredHTTPSig)
		}

		if spec.BodyLimitBytes != service.OCMProtocolBodyLimitBytes {
			t.Errorf("spec %q body limit = %d, want %d",
				spec.ID, spec.BodyLimitBytes, service.OCMProtocolBodyLimitBytes)
		}

		if spec.BodyLimitBytes <= 0 {
			t.Errorf("spec %q body limit = %d, want positive", spec.ID, spec.BodyLimitBytes)
		}

		if spec.PeerResolution == "" {
			t.Errorf("spec %q peer resolution is empty", spec.ID)
		}
	}
}

func TestRegisteredRouteSpecs_CustomTokenPath(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	opts.TokenExchangePath = "exchange"
	specs := registeredRouteSpecs(opts)
	found := false

	for _, spec := range specs {
		if spec.Pattern == "/exchange" {
			found = true
		}
	}

	if !found {
		t.Fatal("expected token route spec for custom path /exchange")
	}
}
