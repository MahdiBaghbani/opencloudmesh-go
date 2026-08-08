// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package resolve_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestResolve_AppliesServiceLocalDefaults(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.Resolve(c, nil, resolve.ResolveInputs{})

	if in.Params.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider default 'OpenCloudMesh', got %q", in.Params.Provider)
	}
}

func TestResolve_DerivesEndPointAndWebDAVRoot(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("expected derived endPoint, got %q", built.Params.EndPoint)
	}

	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}

	if built.Params.WebDAVReceiveURI != "relative" {
		t.Errorf("WebDAVReceiveURI = %q, want relative", built.Params.WebDAVReceiveURI)
	}
}

func TestResolve_SkipsEndPointDerivationWithoutPublicOrigin(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ExternalBasePath: "/ocm"},
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.EndPoint != "" {
		t.Errorf("expected empty endPoint without Origin, got %q", built.Params.EndPoint)
	}

	if built.Params.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("expected derived webdav_root, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_RawConfigWinsOverDerivationForWebDAVRoot(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{
		WebDAVRoot: "/explicit/dav/",
	}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
	}
	raw := map[string]any{
		"webdav_root": "/explicit/dav/",
	}

	built := resolve.Resolve(c, raw, in)

	if built.Params.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("expected derived endPoint, got %q", built.Params.EndPoint)
	}

	if built.Params.WebDAVRoot != "/explicit/dav/" {
		t.Errorf("expected explicit webdav_root preserved, got %q", built.Params.WebDAVRoot)
	}
}

func TestResolve_TokenEndPointDefault(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", ""),
		RouteOpts:     service.DefaultRouteOpts(),
	}

	built := resolve.Resolve(c, nil, in)

	if built.Params.TokenEndPoint != "https://example.com/ocm/token" {
		t.Errorf("expected default token endpoint, got %q", built.Params.TokenEndPoint)
	}
}

func TestResolve_DerivesInviteAcceptDialogFromRouteInventory(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			InviteAcceptEnabled: true,
		},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("expected derived inviteAcceptDialog, got %q", built.Params.InviteAcceptDialog)
	}
}

func TestResolve_SkipsInviteAcceptDialogWithoutPublicOrigin(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ExternalBasePath: "/ocm"},
		RouteOpts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			InviteAcceptEnabled: true,
		},
	}

	built := resolve.Resolve(c, map[string]any{}, in)

	if built.Params.InviteAcceptDialog != "" {
		t.Errorf("expected empty inviteAcceptDialog without Origin, got %q", built.Params.InviteAcceptDialog)
	}
}

// TestResolve_ThreadsJwksURIOverrideIntoBuildParams confirms a configured
// signature.jwks_uri override flows from ResolveInputs.JwksURIOverride into
// discovery.BuildParams.JwksURI unchanged.
func TestResolve_ThreadsJwksURIOverrideIntoBuildParams(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity:   tslocalid.MustTestIdentity(t, "https://cloud.example.com", ""),
		RouteOpts:       service.DefaultRouteOpts(),
		JwksURIOverride: "https://cloud.example.com/custom/jwks.json",
	}

	built := resolve.Resolve(c, nil, in)

	if built.Params.JwksURI != "https://cloud.example.com/custom/jwks.json" {
		t.Errorf("Params.JwksURI = %q, want configured override", built.Params.JwksURI)
	}
}

// TestResolve_EmptyJwksURIOverrideDerivesFromRouteInventory confirms an empty
// override falls back to the route-inventory-derived local default
// (<endPoint>/jwks) rather than leaving BuildParams.JwksURI empty.
func TestResolve_EmptyJwksURIOverrideDerivesFromRouteInventory(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", ""),
		RouteOpts:     service.DefaultRouteOpts(),
	}

	built := resolve.Resolve(c, nil, in)

	if built.Params.JwksURI != "https://cloud.example.com/ocm/jwks" {
		t.Errorf("Params.JwksURI = %q, want https://cloud.example.com/ocm/jwks", built.Params.JwksURI)
	}
}

// TestResolve_EmptyJwksURIOverrideAndNoOriginLeavesBuildParamsEmpty confirms
// that without Origin (so no route projection is possible either) and an
// empty override, BuildParams.JwksURI stays empty.
func TestResolve_EmptyJwksURIOverrideAndNoOriginLeavesBuildParamsEmpty(t *testing.T) {
	t.Parallel()

	c := &resolve.ProviderConfig{}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{},
		RouteOpts:     service.DefaultRouteOpts(),
	}

	built := resolve.Resolve(c, nil, in)

	if built.Params.JwksURI != "" {
		t.Errorf("Params.JwksURI = %q, want empty without Origin or override", built.Params.JwksURI)
	}
}

func newPeerMappingResolver(t *testing.T, cfg *config.PeerMappingConfig, scope config.CompatibilityScope) *policy.PeerMappingResolver {
	t.Helper()

	return policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, scope)
}

// TestResolve_GlobalScope_AppliesGlobalKnobs confirms that under global
// compatibility scope, the global peer_compat knobs still affect the local
// discovery document.
func TestResolve_GlobalScope_AppliesGlobalKnobs(t *testing.T) {
	t.Parallel()

	falseVal := false
	cfg := &config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
	}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ProviderDomain: "unmapped.example"},
		Resolver:      newPeerMappingResolver(t, cfg, config.CompatibilityScopeGlobal),
	}

	built := resolve.Resolve(&resolve.ProviderConfig{}, nil, in)

	if got := built.Params.RequiresTokenExchange; got {
		t.Errorf("global scope should apply global peer_compat knobs; RequiresTokenExchange = %v, want false", got)
	}
}

// TestResolve_ScopedScope_KnobsDoNotLeakToUnmappedHost confirms that under
// scoped compatibility scope, global peer_compat knobs are not leaked to
// unmapped hosts in the discovery document.
func TestResolve_ScopedScope_KnobsDoNotLeakToUnmappedHost(t *testing.T) {
	t.Parallel()

	falseVal := false
	cfg := &config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
	}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ProviderDomain: "unmapped.example"},
		Resolver:      newPeerMappingResolver(t, cfg, config.CompatibilityScopeScoped),
	}

	built := resolve.Resolve(&resolve.ProviderConfig{}, nil, in)

	if got := built.Params.RequiresTokenExchange; !got {
		t.Errorf("scoped scope must not leak global knobs to unmapped hosts; RequiresTokenExchange = %v, want true", got)
	}
}

// TestResolve_ScopedScope_KnobsApplyToMappedHost confirms that under scoped
// compatibility scope, peer_compat knobs still apply when the local host is
// explicitly mapped.
func TestResolve_ScopedScope_KnobsApplyToMappedHost(t *testing.T) {
	t.Parallel()

	falseVal := false
	cfg := &config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
		HostPlatform: map[string]string{
			"mapped.example": "platform-a",
		},
	}
	in := resolve.ResolveInputs{
		LocalIdentity: localidentity.Identity{ProviderDomain: "mapped.example"},
		Resolver:      newPeerMappingResolver(t, cfg, config.CompatibilityScopeScoped),
	}

	built := resolve.Resolve(&resolve.ProviderConfig{}, nil, in)

	if got := built.Params.RequiresTokenExchange; got {
		t.Errorf("scoped scope should apply knobs to mapped hosts; RequiresTokenExchange = %v, want false", got)
	}
}

// TestResolve_ProtocolRolesInDiscoveryDocument verifies that the resolved
// discovery document emits the webdav and webdav-receive protocol roles.
func TestResolve_ProtocolRolesInDiscoveryDocument(t *testing.T) {
	t.Parallel()
	in := resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
		RouteOpts:     service.RouteOpts{ExternalBasePath: "/ocm"},
		Resolver:      newPeerMappingResolver(t, &config.PeerMappingConfig{}, config.CompatibilityScopeGlobal),
	}

	built := resolve.Resolve(&resolve.ProviderConfig{}, map[string]any{}, in)
	disc := discovery.BuildDiscovery(built.Params, nil)

	if !disc.Enabled {
		t.Fatal("expected enabled discovery document")
	}

	if _, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav"); !ok {
		t.Error("expected webdav protocol role in discovery document")
	}

	if _, ok := disc.ResourceTypes[0].Protocols.WebDAVReceive(); !ok {
		t.Error("expected webdav-receive protocol role in discovery document")
	}
}

// TestResolve_ThreadsAdvertiseFlagsIntoCriteria confirms ResolveInputs
// advertise flags flow through Resolve into the built discovery document
// criteria (not only BuildParams).
func TestResolve_ThreadsAdvertiseFlagsIntoCriteria(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		advertiseDenylist   bool
		advertiseAllowlist  bool
		advertiseMustInvite bool
		wantDenylist        bool
		wantAllowlist       bool
		wantMustInvite      bool
	}{
		{
			name:                "all true",
			advertiseDenylist:   true,
			advertiseAllowlist:  true,
			advertiseMustInvite: true,
			wantDenylist:        true,
			wantAllowlist:       true,
			wantMustInvite:      true,
		},
		{
			name:                "all false",
			advertiseDenylist:   false,
			advertiseAllowlist:  false,
			advertiseMustInvite: false,
			wantDenylist:        false,
			wantAllowlist:       false,
			wantMustInvite:      false,
		},
		{
			name:                "must-invite only",
			advertiseDenylist:   false,
			advertiseAllowlist:  false,
			advertiseMustInvite: true,
			wantDenylist:        false,
			wantAllowlist:       false,
			wantMustInvite:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := resolve.ResolveInputs{
				LocalIdentity:       tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm"),
				RouteOpts:           service.RouteOpts{ExternalBasePath: "/ocm"},
				AdvertiseDenylist:   tt.advertiseDenylist,
				AdvertiseAllowlist:  tt.advertiseAllowlist,
				AdvertiseMustInvite: tt.advertiseMustInvite,
			}

			built := resolve.Resolve(&resolve.ProviderConfig{}, map[string]any{}, in)
			disc := discovery.BuildDiscovery(built.Params, nil)

			if got := disc.HasCriteria(spec.CriteriaDenylist); got != tt.wantDenylist {
				t.Errorf("HasCriteria(denylist) = %v, want %v", got, tt.wantDenylist)
			}

			if got := disc.HasCriteria(spec.CriteriaAllowlist); got != tt.wantAllowlist {
				t.Errorf("HasCriteria(allowlist) = %v, want %v", got, tt.wantAllowlist)
			}

			if got := disc.HasCriteria(spec.CriteriaMustInvite); got != tt.wantMustInvite {
				t.Errorf("HasCriteria(must-invite) = %v, want %v", got, tt.wantMustInvite)
			}
		})
	}
}
