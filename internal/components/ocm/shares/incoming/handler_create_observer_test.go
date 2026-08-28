// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func TestCreateShare_ObserverRunsOnFreshCreate(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	var calls atomic.Int64

	handler.SetCreateObserver(func(_ context.Context, share *incoming.IncomingShare) error {
		calls.Add(1)

		if share.ProviderID != "abc123" {
			t.Errorf("observed provider id = %q, want %q", share.ProviderID, "abc123")
		}

		return nil
	})

	w := postCreateShare(t, handler, validShareBodyWithHosts("user-a-uuid@localhost:9200", ownerHost))

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if calls.Load() != 1 {
		t.Fatalf("observer calls = %d, want 1", calls.Load())
	}
}

func TestCreateShare_ObserverRunsOnMatchingDuplicate(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	var calls atomic.Int64

	handler.SetCreateObserver(func(_ context.Context, _ *incoming.IncomingShare) error {
		calls.Add(1)

		return nil
	})

	body := validShareBodyWithHosts("user-a-uuid@localhost:9200", ownerHost)

	if w := postCreateShare(t, handler, body); w.Code != http.StatusCreated {
		t.Fatalf("first post: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// The idempotent retry hits the matching-duplicate path, which must run
	// the same observer before encoding its 201.
	if w := postCreateShare(t, handler, body); w.Code != http.StatusCreated {
		t.Fatalf("duplicate post: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if calls.Load() != 2 {
		t.Fatalf("observer calls = %d, want 2 (fresh create plus duplicate retry)", calls.Load())
	}
}

func TestCreateShare_ObserverErrorSuppressesCreated(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	handler.SetCreateObserver(func(_ context.Context, _ *incoming.IncomingShare) error {
		return errors.New("injected observer failure")
	})

	w := postCreateShare(t, handler, validShareBodyWithHosts("user-a-uuid@localhost:9200", ownerHost))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 storage error, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_MismatchedDuplicateStaysHookFree(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	partyRepo := setupTestPartyRepo(t)
	handler, ownerHost := newAcceptedShareHandler(t, repo, partyRepo)

	var calls atomic.Int64

	handler.SetCreateObserver(func(_ context.Context, _ *incoming.IncomingShare) error {
		calls.Add(1)

		return nil
	})

	body := validShareBodyWithHosts("user-a-uuid@localhost:9200", ownerHost)

	if w := postCreateShare(t, handler, body); w.Code != http.StatusCreated {
		t.Fatalf("first post: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Same provider id and sender but a changed name: the 409 conflict path
	// must never invoke the observer.
	mismatched := strings.Replace(body, `"name": "test.txt"`, `"name": "other.txt"`, 1)

	w := postCreateShare(t, handler, mismatched)

	if w.Code != http.StatusConflict {
		t.Fatalf("mismatched duplicate: expected 409, got %d: %s", w.Code, w.Body.String())
	}

	if calls.Load() != 1 {
		t.Fatalf("observer calls = %d, want 1 (409 path stays hook-free)", calls.Load())
	}
}
