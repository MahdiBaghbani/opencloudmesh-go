// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

type startCreateBody struct {
	ID string `json:"id"`
}

type sessionPollBody struct {
	State           string `json:"state"`
	NextInstruction string `json:"nextInstruction"`
}

type stopAbortBody struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

type claimInviteBody struct {
	InviteString string `json:"inviteString"`
}

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

func assertOptInActiveUnavailable(t *testing.T, baseURL, target string) {
	t.Helper()

	status, raw := doJSON(t, http.MethodPost, baseURL+validatorStartPath, map[string]any{
		"target":      target,
		"optInActive": true,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("POST start optInActive status = %d body=%s, want 400", status, raw)
	}

	var startErr map[string]string
	if err := json.Unmarshal(raw, &startErr); err != nil {
		t.Fatalf("decode start error: %v body=%s", err, raw)
	}

	if startErr["error"] != "opt_in_active_unavailable" {
		t.Fatalf("start error = %q, want opt_in_active_unavailable", startErr["error"])
	}

	if startErr["message"] != "active opt-in is unavailable in this deployment" {
		t.Fatalf("start message = %q, want active opt-in is unavailable in this deployment", startErr["message"])
	}
}

func assertPassiveOnlyManifestHasScan(t *testing.T, baseURL string) {
	t.Helper()

	manifestStatus, manifestRaw := doJSON(t, http.MethodGet, baseURL+"/validator/api/manifest", nil)
	if manifestStatus != http.StatusOK {
		t.Fatalf("GET manifest status = %d body=%s, want 200", manifestStatus, manifestRaw)
	}

	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decode manifest: %v body=%s", err, manifestRaw)
	}

	if _, ok := manifest["scan"]; !ok {
		t.Fatal("passive-only manifest must advertise scan")
	}

	var routes []struct {
		Method   string `json:"method"`
		FullPath string `json:"fullPath"`
	}
	if err := json.Unmarshal(manifest["routes"], &routes); err != nil {
		t.Fatalf("decode manifest routes: %v", err)
	}

	hasScanRoute := false

	for _, route := range routes {
		if route.Method == http.MethodGet && route.FullPath == validatorScanPath {
			hasScanRoute = true
		}
	}

	if !hasScanRoute {
		t.Fatalf("passive-only manifest routes missing GET scan: %+v", routes)
	}
}

func assertScanRejectsLoopback(t *testing.T, baseURL string) {
	t.Helper()

	loopbackURL := baseURL + validatorScanPath + "?target=" + url.QueryEscape("https://127.0.0.1")

	loopbackStatus, loopbackRaw := doJSON(t, http.MethodGet, loopbackURL, nil)
	if loopbackStatus != http.StatusBadRequest {
		t.Fatalf("GET scan loopback status = %d body=%s, want 400", loopbackStatus, loopbackRaw)
	}

	if bytes.Contains(loopbackRaw, []byte("127.0.0.1")) {
		t.Fatalf("loopback scan error echoed input: %s", loopbackRaw)
	}

	var loopbackErr map[string]string
	if err := json.Unmarshal(loopbackRaw, &loopbackErr); err != nil {
		t.Fatalf("decode loopback error: %v body=%s", err, loopbackRaw)
	}

	if loopbackErr["error"] != "target_not_public" {
		t.Fatalf("loopback error = %q, want target_not_public", loopbackErr["error"])
	}

	if loopbackErr["message"] != "target must be a public address" {
		t.Fatalf("loopback message = %q, want target must be a public address", loopbackErr["message"])
	}
}

func postStart(t *testing.T, baseURL, target string, optInActive bool) string {
	t.Helper()

	payload := map[string]any{"target": target}
	if optInActive {
		payload["optInActive"] = true
	}

	status, raw := doJSON(t, http.MethodPost, baseURL+validatorStartPath, payload)
	if status != http.StatusCreated {
		t.Fatalf("POST start status = %d body=%s, want 201", status, raw)
	}

	return decodeStartID(t, raw)
}

func getScan(t *testing.T, baseURL, target string) string {
	t.Helper()

	scanURL := baseURL + validatorScanPath + "?target=" + url.QueryEscape(target)

	status, raw := doJSON(t, http.MethodGet, scanURL, nil)
	if status != http.StatusCreated {
		t.Fatalf("GET scan status = %d body=%s, want 201", status, raw)
	}

	return decodeStartID(t, raw)
}

func decodeStartID(t *testing.T, raw []byte) string {
	t.Helper()

	var created startCreateBody
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode start/scan: %v body=%s", err, raw)
	}

	if created.ID == "" {
		t.Fatalf("missing session id in %s", raw)
	}

	return created.ID
}

func pollSession(t *testing.T, pollCtx context.Context, baseURL, id string) sessionPollBody {
	t.Helper()

	reqCtx, cancel := context.WithTimeout(pollCtx, sessionPollRequestTimeout)
	defer cancel()

	status, raw := doJSONWithContext(
		t,
		reqCtx,
		http.MethodGet,
		baseURL+validatorSessionPath+id,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("GET session status = %d body=%s, want 200", status, raw)
	}

	var poll sessionPollBody
	if err := json.Unmarshal(raw, &poll); err != nil {
		t.Fatalf("decode session poll: %v body=%s", err, raw)
	}

	return poll
}

func waitSessionState(t *testing.T, baseURL, id string, want ...string) {
	t.Helper()

	allowed := make(map[string]struct{}, len(want))
	for _, state := range want {
		allowed[state] = struct{}{}
	}

	waitSession(t, baseURL, id, func(poll sessionPollBody) bool {
		_, ok := allowed[poll.State]

		return ok
	})
}

func waitSessionInstruction(t *testing.T, baseURL, id, want string) {
	t.Helper()

	waitSession(t, baseURL, id, func(poll sessionPollBody) bool {
		return poll.NextInstruction == want
	})
}

func waitSession(
	t *testing.T,
	baseURL, id string,
	ready func(sessionPollBody) bool,
) {
	t.Helper()

	ctx := t.Context()

	pollCtx, cancelPoll := context.WithTimeout(ctx, sessionPollTimeout)
	defer cancelPoll()

	deadline := time.NewTimer(sessionPollTimeout)
	defer deadline.Stop()

	ticker := time.NewTicker(sessionPollEvery)
	defer ticker.Stop()

	var last sessionPollBody

	for {
		if ctx.Err() != nil {
			t.Fatalf(
				"session %s poll cancelled: %v last=%+v",
				id,
				context.Cause(ctx),
				last,
			)
		}

		last = pollSession(t, pollCtx, baseURL, id)
		if ready(last) {
			return
		}

		if isSessionTerminal(last.State) {
			t.Fatalf(
				"session %s unexpected terminal state=%q nextInstruction=%q last=%+v",
				id,
				last.State,
				last.NextInstruction,
				last,
			)
		}

		select {
		case <-ctx.Done():
			t.Fatalf(
				"session %s poll cancelled: %v last=%+v",
				id,
				context.Cause(ctx),
				last,
			)
		case <-deadline.C:
			t.Fatalf("timeout waiting for session %s, last=%+v", id, last)
		case <-ticker.C:
		}
	}
}

func isSessionTerminal(state string) bool {
	switch state {
	case stateTerminalPass, stateTerminalFail, stateInterrupted:
		return true
	default:
		return false
	}
}

func postStop(t *testing.T, baseURL, id string) string {
	t.Helper()

	status, raw := doJSON(t, http.MethodPost, baseURL+validatorStopPath, map[string]string{"id": id})
	if status != http.StatusOK {
		t.Fatalf("POST stop status = %d body=%s, want 200", status, raw)
	}

	return decodeStopAbortState(t, raw)
}

func postAbort(t *testing.T, baseURL, id string) string {
	t.Helper()

	status, raw := doJSON(t, http.MethodPost, baseURL+validatorSessionPath+id+"/abort", nil)
	if status != http.StatusOK {
		t.Fatalf("POST abort status = %d body=%s, want 200", status, raw)
	}

	return decodeStopAbortState(t, raw)
}

func decodeStopAbortState(t *testing.T, raw []byte) string {
	t.Helper()

	var payload stopAbortBody
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode stop/abort: %v body=%s", err, raw)
	}

	return payload.State
}

func postClaim(t *testing.T, baseURL, id string) claimInviteBody {
	t.Helper()

	status, raw := doJSON(t, http.MethodPost, baseURL+validatorSessionPath+id+"/invite", nil)
	if status != http.StatusOK {
		t.Fatalf("POST claim status = %d body=%s, want 200", status, raw)
	}

	var claimed claimInviteBody
	if err := json.Unmarshal(raw, &claimed); err != nil {
		t.Fatalf("decode claim: %v body=%s", err, raw)
	}

	if claimed.InviteString == "" {
		t.Fatalf("claim missing inviteString: %s", raw)
	}

	return claimed
}

func doJSON(t *testing.T, method, rawURL string, payload any) (int, []byte) {
	t.Helper()

	return doJSONWithContext(t, t.Context(), method, rawURL, payload)
}

func doJSONWithContext(
	t *testing.T,
	ctx context.Context,
	method, rawURL string,
	payload any,
) (int, []byte) {
	t.Helper()

	var body io.Reader

	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, rawURL, err)
		}

		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, rawURL, err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed by tshttp.MustClose
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer tshttp.MustClose(t, resp.Body)

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, rawURL, err)
	}

	return resp.StatusCode, raw
}
