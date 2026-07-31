// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	tsinvite "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/invite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
	tsession "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/session"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestInviteAcceptTwoInstanceAPI proves the MVP API path: Alice creates an
// outgoing invite, Bob imports and accepts it, Bob notifies Alice via
// POST /ocm/invite-accepted, and both sides record accepted state.
func TestInviteAcceptTwoInstanceAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	alice, bob := startStrictInvitePair(t, false)
	defer alice.Stop(t)
	defer bob.Stop(t)

	aliceClient := alice.Client()
	bobClient := bob.Client()

	aliceToken, err := tsession.Login(t.Context(), aliceClient, alice.BaseURL, "admin", "")
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("login alice: %v", err)
	}

	created, _, err := tsinvite.CreateOutgoing(t.Context(), aliceClient, alice.BaseURL, aliceToken)
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("alice create outgoing invite: %v", err)
	}

	bobToken, err := tsession.Login(t.Context(), bobClient, bob.BaseURL, "admin", "")
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("login bob: %v", err)
	}

	imported, _, err := tsinvite.Import(t.Context(), bobClient, bob.BaseURL, bobToken, created.InviteString)
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("bob import invite: %v", err)
	}

	if imported.Status != invites.InviteStatusPending {
		t.Fatalf("imported status = %q, want pending", imported.Status)
	}

	if _, _, aerr := tsinvite.Accept(t.Context(), bobClient, bob.BaseURL, bobToken, imported.ID); aerr != nil {
		alice.DumpLogs(t)
		bob.DumpLogs(t)
		t.Fatalf("bob accept invite: %v", aerr)
	}

	list, _, err := tsinvite.ListInbox(t.Context(), bobClient, bob.BaseURL, bobToken)
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("bob list inbox invites: %v", err)
	}

	bobInvite, err := tsinvite.FindInboxInvite(list, imported.ID)
	if err != nil {
		t.Fatalf("bob inbox missing accepted invite: %v", err)
	}

	if bobInvite.Status != invites.InviteStatusAccepted {
		t.Fatalf("bob inbox status = %q, want accepted", bobInvite.Status)
	}

	status, acceptedBy, err := tsinvite.OutgoingStatus(alice.TempDir, created.Token)
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("read alice outgoing invite status: %v", err)
	}

	if status != invites.InviteStatusAccepted {
		t.Fatalf("alice outgoing status = %q, want accepted", status)
	}

	if acceptedBy == "" {
		t.Fatal("alice outgoing invite missing accepted_by recipient provider")
	}

	if !strings.Contains(acceptedBy, "localhost") {
		t.Fatalf("accepted_by = %q, expected bob localhost provider", acceptedBy)
	}
}

func startStrictInvitePair(t *testing.T, enableWAYF bool) (*harness.SubprocessServer, *harness.SubprocessServer) {
	t.Helper()

	binaryPath := harness.BuildBinary(t)
	moduleRoot := modroot.ModuleRoot(t)
	caCert := tsinvite.StrictInstanceTLSRootCA(moduleRoot)
	extra := tsinvite.StrictInstanceExtraConfig(tsinvite.StrictInstanceOptions{
		ModuleRoot:      moduleRoot,
		EnableWAYF:      enableWAYF,
		JSONPersistence: true,
	})

	cfg := harness.SubprocessConfig{
		Name: "alice",
		Mode: "dev",
		// Dev mode plus StrictInstanceExtraConfig keeps loopback-friendly
		// transport while static TLS and SSRF-off extra config drive discovery.
		DisableUseEnvFallback:  true,
		TLSRootCAFile:          caCert,
		BootstrapAdminPassword: "testpassword123",
		ExtraConfig:            extra,
	}

	aliceCfg := cfg
	aliceCfg.Name = "alice"
	bobCfg := cfg
	bobCfg.Name = "bob"

	return harness.StartSubprocessServer(t, binaryPath, aliceCfg),
		harness.StartSubprocessServer(t, binaryPath, bobCfg)
}
