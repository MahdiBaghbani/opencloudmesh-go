// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleClaimInvite_FirstReturnsSafeFields(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-first"
	token := env.seedMinted(t, runID)

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	payload := decodeClaimJSON(t, rec)
	assertExactKeys(t, payload, []string{
		"expiresAt",
		"inviteString",
		"issuerFqdn",
		"pasteTargetHost",
		"pasteTargetOrigin",
	})

	var issuer, origin, host, inviteString string
	if err := json.Unmarshal(payload["issuerFqdn"], &issuer); err != nil {
		t.Fatalf("issuerFqdn: %v", err)
	}

	if err := json.Unmarshal(payload["pasteTargetOrigin"], &origin); err != nil {
		t.Fatalf("pasteTargetOrigin: %v", err)
	}

	if err := json.Unmarshal(payload["pasteTargetHost"], &host); err != nil {
		t.Fatalf("pasteTargetHost: %v", err)
	}

	if err := json.Unmarshal(payload["inviteString"], &inviteString); err != nil {
		t.Fatalf("inviteString: %v", err)
	}

	if issuer != claimTestLocalDomain {
		t.Fatalf("issuerFqdn = %q, want %q", issuer, claimTestLocalDomain)
	}

	if origin != claimTestTargetOrigin {
		t.Fatalf("pasteTargetOrigin = %q, want %q", origin, claimTestTargetOrigin)
	}

	if host != claimTestTargetHost {
		t.Fatalf("pasteTargetHost = %q, want %q", host, claimTestTargetHost)
	}

	if inviteString == "" {
		t.Fatal("inviteString is empty")
	}

	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("response includes a token field: %s", rec.Body.String())
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), inviteString) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_SecondReturnsGoneWithoutInvite(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-second"
	token := env.seedMinted(t, runID)

	first := doClaim(t, env.handler, runID)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	var firstBody map[string]string
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusGone {
		t.Fatalf("second status = %d, want 410 (body %s)", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeInviteAlreadyClaimed {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeInviteAlreadyClaimed)
	}

	body := rec.Body.String()
	if strings.Contains(body, firstBody["inviteString"]) || strings.Contains(body, token) {
		t.Fatalf("410 body leaked invite material: %s", body)
	}

	if _, ok := payload["inviteString"]; ok {
		t.Fatal("410 body includes inviteString")
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), firstBody["inviteString"]) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_ConcurrentSingleDisclosure(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-race"
	token := env.seedMinted(t, runID)

	const workers = 8

	var wg sync.WaitGroup

	codes := make([]int, workers)
	bodies := make([]string, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			rec := doClaim(t, env.handler, runID)
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
		}()
	}

	wg.Wait()

	okCount := 0
	goneCount := 0

	for i, code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusGone:
			goneCount++

			if strings.Contains(bodies[i], token) {
				t.Fatalf("410 body leaked token: %s", bodies[i])
			}
		default:
			t.Fatalf("worker status = %d, want 200 or 410 (body %s)", code, bodies[i])
		}
	}

	if okCount != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", okCount)
	}

	if goneCount < 1 {
		t.Fatal("expected at least one 410")
	}
}

func TestHandleClaimInvite_PollStaysTokenFreeWithPasteS1(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-poll"
	token := env.seedMinted(t, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	claimRouter(env.handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", rec.Code)
	}

	payload := decodeClaimJSON(t, rec)
	assertExactKeys(t, payload, []string{"nextInstruction", "state", "ts"})

	var next string
	if err := json.Unmarshal(payload["nextInstruction"], &next); err != nil {
		t.Fatalf("nextInstruction: %v", err)
	}

	if next != "paste_s1" {
		t.Fatalf("nextInstruction = %q, want paste_s1", next)
	}

	body := rec.Body.String()
	if strings.Contains(body, token) {
		t.Fatalf("poll leaked token: %s", body)
	}

	if strings.Contains(body, "inviteString") {
		t.Fatalf("poll includes inviteString: %s", body)
	}

	claimed := doClaim(t, env.handler, runID)
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim status = %d, want 200", claimed.Code)
	}

	after := doPoll(t, env.handler, runID)

	afterBody := after.Body.String()
	if strings.Contains(afterBody, token) || strings.Contains(afterBody, "inviteString") {
		t.Fatalf("post-claim poll leaked invite material: %s", afterBody)
	}

	afterPayload := decodeClaimJSON(t, after)
	if pollNextInstruction(t, afterPayload) != "paste_s1" {
		t.Fatalf("post-claim nextInstruction = %s, want paste_s1", afterPayload["nextInstruction"])
	}
}
