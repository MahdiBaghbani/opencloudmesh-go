package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestCapabilityWireValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "http-sig", got: spec.CapabilityHTTPSig, want: "http-sig"},
		{name: "exchange-token", got: spec.CapabilityExchangeToken, want: "exchange-token"},
		{name: "invites", got: spec.CapabilityInvite, want: "invites"},
		{name: "invite-wayf", got: spec.CapabilityInviteWAYF, want: "invite-wayf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("wire value = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestCapabilityInviteMatchesOutboundEndpointKindWireValue(t *testing.T) {
	if spec.CapabilityInvite != string(outbound.EndpointInvites) {
		t.Fatalf("CapabilityInvite = %q, EndpointInvites = %q; wire vocabulary should match",
			spec.CapabilityInvite, outbound.EndpointInvites)
	}
}

func TestDiscoveryHelpersUseCapabilityConstants(t *testing.T) {
	disc := &spec.Discovery{
		Capabilities:  []string{spec.CapabilityHTTPSig, spec.CapabilityExchangeToken},
		TokenEndPoint: "https://example.com/ocm/token",
	}
	if !disc.IsHTTPSigCapable() {
		t.Error("IsHTTPSigCapable() = false, want true")
	}

	if !disc.SupportsTokenExchange() {
		t.Error("SupportsTokenExchange() = false, want true")
	}

	if disc.HasCapability(spec.CapabilityInvite) {
		t.Error("HasCapability(CapabilityInvite) = true, want false")
	}
}

// capabilityClosedPathFiles are production files on the closed migration path.
// Each must not contain raw capability wire string literals; use spec.*.
var capabilityClosedPathFiles = []string{
	"internal/components/ocm/spec/discovery.go",
	"internal/components/ocm/discovery/builder.go",
	"internal/components/ocm/discovery/validate.go",
	"internal/components/ocm/access/remote.go",
	"internal/components/ocm/policy/compiler.go",
}

var capabilityWireLiterals = []string{
	`"http-sig"`,
	`"exchange-token"`,
	`"invites"`,
	`"invite-wayf"`,
}

func TestCapabilityClosedPathNoRawWireLiterals(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for _, rel := range capabilityClosedPathFiles {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			content := string(data)
			for _, lit := range capabilityWireLiterals {
				if strings.Contains(content, lit) {
					t.Errorf("%s still contains raw capability literal %s; use spec.*", rel, lit)
				}
			}
		})
	}
}
