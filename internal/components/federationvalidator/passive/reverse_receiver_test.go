// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleStart_ExtendMaterializesReverseReceiver(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	parties := identity.NewMemoryPartyRepo()
	h := NewHandler(store, nil)
	h.SetReverseReceiver(
		parties,
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-extend-bob"

	if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"id": runID})),
	)
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("extend status = %d, want 200", rec.Code)
	}

	run, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		t.Fatal("bob_user_id is empty after extend")
	}

	bob, err := parties.Get(ctx, *run.BobUserID)
	if err != nil {
		t.Fatalf("Get bob party: %v", err)
	}

	if bob.ID != *run.BobUserID {
		t.Fatalf("bob id = %q, want %q", bob.ID, *run.BobUserID)
	}

	if bob.DisplayName != config.DefaultValidatorProbeDisplayName {
		t.Fatalf("bob display name = %q", bob.DisplayName)
	}

	if bob.Role != identity.RoleProbe || bob.ExpiresAt != nil {
		t.Fatalf("bob party = %+v", bob)
	}

	if _, err := parties.Get(ctx, runID); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("alice must not be created at extend, err=%v", err)
	}
}
