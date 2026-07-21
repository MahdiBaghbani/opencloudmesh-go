package resolve_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
)

func testNextcloudContract(t *testing.T) *peercompat.CompiledContract {
	t.Helper()
	contract, err := peercompat.NewCompiledContract(
		nil,
		[]peercompat.ProfileMapping{{Pattern: "nc.example.com", Profile: "nextcloud"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}
	return contract
}

func TestSelectAPIVersionOverride_MatchedPeerAndUserAgent(t *testing.T) {
	contract := testNextcloudContract(t)
	overrides := []resolve.APIVersionOverride{{
		Profile:           "nextcloud",
		UserAgentContains: "Nextcloud Server Crawler",
		APIVersion:        "1.1",
	}}

	version, ok := resolve.SelectAPIVersionOverride(
		overrides,
		contract,
		"nc.example.com",
		"Nextcloud Server Crawler/1.0",
	)
	if !ok {
		t.Fatal("expected override to activate")
	}
	if version != "1.1" {
		t.Fatalf("expected apiVersion 1.1, got %q", version)
	}
}

func TestSelectAPIVersionOverride_UserAgentOnlyDoesNotActivate(t *testing.T) {
	contract := testNextcloudContract(t)
	overrides := []resolve.APIVersionOverride{{
		Profile:           "nextcloud",
		UserAgentContains: "Nextcloud Server Crawler",
		APIVersion:        "1.1",
	}}

	if _, ok := resolve.SelectAPIVersionOverride(
		overrides,
		contract,
		"",
		"Nextcloud Server Crawler/1.0",
	); ok {
		t.Fatal("expected empty peer identity to fail closed")
	}
}

func TestSelectAPIVersionOverride_MatchedPeerWrongUserAgent(t *testing.T) {
	contract := testNextcloudContract(t)
	overrides := []resolve.APIVersionOverride{{
		Profile:           "nextcloud",
		UserAgentContains: "Nextcloud Server Crawler",
		APIVersion:        "1.1",
	}}

	if _, ok := resolve.SelectAPIVersionOverride(
		overrides,
		contract,
		"nc.example.com",
		"OtherClient/1.0",
	); ok {
		t.Fatal("expected nonmatching User-Agent to fail closed")
	}
}

func TestSelectAPIVersionOverride_UnmatchedPeer(t *testing.T) {
	contract := testNextcloudContract(t)
	overrides := []resolve.APIVersionOverride{{
		Profile:           "nextcloud",
		UserAgentContains: "Nextcloud Server Crawler",
		APIVersion:        "1.1",
	}}

	if _, ok := resolve.SelectAPIVersionOverride(
		overrides,
		contract,
		"unknown.example.com",
		"Nextcloud Server Crawler/1.0",
	); ok {
		t.Fatal("expected unmatched peer to fail closed")
	}
}

func TestSelectAPIVersionOverride_NilContract(t *testing.T) {
	overrides := []resolve.APIVersionOverride{{
		Profile:           "nextcloud",
		UserAgentContains: "Nextcloud Server Crawler",
		APIVersion:        "1.1",
	}}

	if _, ok := resolve.SelectAPIVersionOverride(
		overrides,
		nil,
		"nc.example.com",
		"Nextcloud Server Crawler/1.0",
	); ok {
		t.Fatal("expected nil contract to fail closed")
	}
}

func TestResolve_FiltersOverridesWithoutProfileBinding(t *testing.T) {
	contract := testNextcloudContract(t)
	c := &resolve.ProviderConfig{
		APIVersionOverrides: []resolve.APIVersionOverride{
			{
				UserAgentContains: "Nextcloud Server Crawler",
				APIVersion:        "1.1",
			},
			{
				Profile:           "nextcloud",
				UserAgentContains: "Nextcloud Server Crawler",
				APIVersion:        "1.1",
			},
		},
	}

	built := resolve.Resolve(c, nil, resolve.ResolveInputs{PeerContract: contract})
	if len(built.Overrides) != 1 {
		t.Fatalf("expected one bound override, got %d", len(built.Overrides))
	}
	if built.Overrides[0].Profile != "nextcloud" {
		t.Fatalf("expected nextcloud profile, got %q", built.Overrides[0].Profile)
	}
}

func TestResolve_FiltersOverridesWithoutContract(t *testing.T) {
	c := &resolve.ProviderConfig{
		APIVersionOverrides: []resolve.APIVersionOverride{{
			Profile:           "nextcloud",
			UserAgentContains: "Nextcloud Server Crawler",
			APIVersion:        "1.1",
		}},
	}

	built := resolve.Resolve(c, nil, resolve.ResolveInputs{})
	if len(built.Overrides) != 0 {
		t.Fatalf("expected no overrides without contract, got %d", len(built.Overrides))
	}
}
