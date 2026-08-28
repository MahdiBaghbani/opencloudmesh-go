// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// inviteAcceptedEndpoint returns the real product invite-accepted handler
// wrapped in the validator decorator, wired on the test repos.
func (e *testEnv) inviteAcceptedEndpoint() http.HandlerFunc {
	product := accepted.NewHandler(e.outgoing, e.parties, nil, testLocalDomain, "https")

	return e.svc.DecorateInviteAccepted(product.HandleInviteAccepted)
}

func postInviteAccepted(t *testing.T, handler http.HandlerFunc, token, recipientProvider string) *httptest.ResponseRecorder {
	t.Helper()

	return postInviteAcceptedAs(t, handler, token, recipientProvider, "accepter-user")
}

func postInviteAcceptedAs(
	t *testing.T,
	handler http.HandlerFunc,
	token, recipientProvider, userID string,
) *httptest.ResponseRecorder {
	t.Helper()

	body := fmt.Sprintf(
		`{"recipientProvider":%s,"token":%s,"userID":%s,"email":"a@example","name":"Accepter"}`,
		strconv.Quote(recipientProvider),
		strconv.Quote(token),
		strconv.Quote(userID),
	)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/ocm/invite-accepted",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler(rec, req)

	return rec
}

func (e *testEnv) requireWrongAccepterHalt(t *testing.T, runID string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if run.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalFail)
	}

	if run.TerminalReason == nil || *run.TerminalReason != validatorcore.ReasonWrongAccepter {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, validatorcore.ReasonWrongAccepter)
	}

	if run.DesignatedShareWith != nil {
		t.Fatalf("designated_share_with = %v, want nil after identity halt", run.DesignatedShareWith)
	}
}

func (e *testEnv) unenforceableAccepterEvidence(t *testing.T, runID string) []validatorcore.EvidenceRow {
	t.Helper()

	var rows []validatorcore.EvidenceRow
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?",
			runID,
			validatorcore.SpecificationAreaSharing,
			"invite_accepted",
			"accepter_user_unenforceable",
		).
		Find(&rows).Error; err != nil {
		t.Fatalf("list unenforceable-accepter evidence: %v", err)
	}

	return rows
}

func (e *testEnv) markInviteAccepted(t *testing.T, inviteID, userID, normalizedHost string) {
	t.Helper()

	err := e.outgoing.UpdateStatus(t.Context(), inviteID, invites.InviteStatusAccepted, &invitesoutgoing.Acceptance{
		ProviderFQDN:           normalizedHost,
		UserID:                 userID,
		ProviderFQDNNormalized: normalizedHost,
	})
	if err != nil {
		t.Fatalf("mark invite accepted: %v", err)
	}
}
