// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"

	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestObserveAccepted_UnexpectedLookupErrorIsReturnedAndLogged(t *testing.T) {
	t.Parallel()

	env := newPersistInternalEnv(t)
	runID := "run-dec-lookup-err"
	invite := env.seedMintedAccepted(t, runID)
	injected := errors.New("injected outgoing invite lookup failure")

	var logs bytes.Buffer

	env.svc.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	env.svc.deps.OutgoingInvites = failLookupInvites{
		OutgoingInviteRepo: env.outgoing,
		err:                injected,
	}

	req, body, resp := inviteAcceptedObserveArgs(t, invite.Token)

	err := env.svc.observeAccepted(req, body, http.StatusOK, resp)
	if err == nil {
		t.Fatal("observeAccepted error = nil, want unexpected lookup failure")
	}

	if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, validatorcore.ErrSessionNotFound) {
		t.Fatalf("observeAccepted mapped lookup failure to a miss sentinel: %v", err)
	}

	if !errors.Is(err, injected) {
		t.Fatalf("observeAccepted error = %v, want wrapped %v", err, injected)
	}

	handler := env.svc.DecorateInviteAccepted(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	httpReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/ocm/invite-accepted",
		strings.NewReader(string(body)),
	)
	rec := httptest.NewRecorder()
	handler(rec, httpReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	logged := logs.String()
	if !strings.Contains(logged, "reverseinvite: observe invite-accepted") {
		t.Fatalf("decorator log missing observe error line: %q", logged)
	}

	if !strings.Contains(logged, injected.Error()) {
		t.Fatalf("decorator log missing injected lookup error: %q", logged)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}

type failLookupInvites struct {
	invitesoutgoing.OutgoingInviteRepo

	err error
}

func (r failLookupInvites) GetByToken(ctx context.Context, token string) (*invitesoutgoing.OutgoingInvite, error) {
	if r.err != nil {
		return nil, r.err
	}

	invite, err := r.OutgoingInviteRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("lookup outgoing invite: %w", err)
	}

	return invite, nil
}
