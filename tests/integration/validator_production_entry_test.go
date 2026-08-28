// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/validatorpeer"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// Production-entry HTTP tests drive start/scan/claim/poll/abort/stop through
// real routes only. Passive sessions assess at most four of eight
// specification areas (discovery, TLS, JWKS, HTTP-sig). An opaque or UUID
// accepter is warn-only; this file does not assert a halt for those forms.

const (
	validatorStartPath   = "/validator/start"
	validatorScanPath    = "/validator/api/scan"
	validatorSessionPath = "/validator/api/session/"
	validatorStopPath    = "/validator/stop"
	inviteAcceptedPath   = "/ocm/invite-accepted"

	statePassiveComplete = "passive_complete"
	stateActiveRunning   = "active_running"
	stateInviteMinted    = "invite_minted"
	stateTerminalPass    = "terminal_pass"
	stateTerminalFail    = "terminal_fail"
	stateInterrupted     = "interrupted"

	instrWaitActiveSlot = "wait_active_slot"

	// Budget for GET /validator/api/session/{id} under make
	// test-integration (-race -coverpkg -shuffle). Isolation is
	// fast; 2s per-GET flakes when SQLite busy_timeout (5s) or a
	// cold first poll exceeds it. Per-GET uses the full
	// sessionPollTimeout so one slow poll does not abort while the
	// outer deadline still has budget. Matches waitForStateDeadline
	// in passive/handler_test.go.
	sessionPollTimeout        = 10 * time.Second
	sessionPollEvery          = 25 * time.Millisecond
	sessionPollRequestTimeout = sessionPollTimeout
)

func TestValidatorProductionEntry_StoreOnlyScanPassiveComplete(t *testing.T) {
	t.Parallel()

	ts := harness.StartPassiveOnlyValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	id := getScan(t, ts.BaseURL, peer.URL)
	waitSessionState(t, ts.BaseURL, id, statePassiveComplete)

	assertOptInActiveUnavailable(t, ts.BaseURL, peer.URL)
	assertPassiveOnlyManifestHasScan(t, ts.BaseURL)
	assertScanRejectsLoopback(t, ts.BaseURL)
}

func TestValidatorProductionEntry_URLTargetTerminalPass(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	id := postStart(t, ts.BaseURL, peer.URL, false)
	waitSessionState(t, ts.BaseURL, id, statePassiveComplete)

	if got := postStop(t, ts.BaseURL, id); got != stateTerminalPass {
		t.Fatalf("stop state = %q, want %q", got, stateTerminalPass)
	}
}

func TestValidatorProductionEntry_OCMIDTargetTerminalPass(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	id := getScan(t, ts.BaseURL, "alice@"+peer.Host)
	waitSessionState(t, ts.BaseURL, id, statePassiveComplete)

	if got := postStop(t, ts.BaseURL, id); got != stateTerminalPass {
		t.Fatalf("stop state = %q, want %q", got, stateTerminalPass)
	}
}

func TestValidatorProductionEntry_AbortTerminalFail(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	id := postStart(t, ts.BaseURL, peer.URL, true)
	waitSessionState(t, ts.BaseURL, id, stateActiveRunning, stateInviteMinted)

	if got := postAbort(t, ts.BaseURL, id); got != stateTerminalFail {
		t.Fatalf("abort state = %q, want %q", got, stateTerminalFail)
	}
}

func TestValidatorProductionEntry_WrongAccepterPlainUserHalt(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	id := postStart(t, ts.BaseURL, "malek@"+peer.Host, true)
	waitSessionState(t, ts.BaseURL, id, stateInviteMinted)

	claimed := postClaim(t, ts.BaseURL, id)

	token, _, err := invites.ParseInviteString(claimed.InviteString)
	if err != nil {
		t.Fatalf("parse invite string: %v", err)
	}

	status, body := tshttp.PostSignedJSONStatusBody(
		t,
		http.DefaultClient,
		peer.Signer,
		ts.BaseURL+inviteAcceptedPath,
		spec.InviteAcceptedRequest{
			RecipientProvider: peer.Host,
			Token:             token,
			UserID:            "omar",
			Email:             "omar@example.com",
			Name:              "Omar",
		},
	)
	if status != http.StatusOK {
		t.Fatalf("invite-accepted status = %d body=%s, want 200", status, body)
	}

	waitSessionState(t, ts.BaseURL, id, stateTerminalFail)
}

func TestValidatorProductionEntry_PassiveFailGate(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{FailDiscovery: true})

	id := postStart(t, ts.BaseURL, peer.URL, false)
	waitSessionState(t, ts.BaseURL, id, stateTerminalFail)
}

func TestValidatorProductionEntry_LockWaitPromote(t *testing.T) {
	t.Parallel()

	ts := harness.StartValidatorServer(t)
	peer := validatorpeer.Start(t, validatorpeer.Options{})

	holder := postStart(t, ts.BaseURL, peer.URL, true)
	waitSessionState(t, ts.BaseURL, holder, stateActiveRunning, stateInviteMinted)

	waiter := postStart(t, ts.BaseURL, peer.URL, true)
	waitSessionInstruction(t, ts.BaseURL, waiter, instrWaitActiveSlot)

	if got := postAbort(t, ts.BaseURL, holder); got != stateTerminalFail {
		t.Fatalf("holder abort state = %q, want %q", got, stateTerminalFail)
	}

	waitSessionState(t, ts.BaseURL, waiter, stateActiveRunning, stateInviteMinted)
}
