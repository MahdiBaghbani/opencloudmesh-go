// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package token

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryTokenStore_CleanExpired(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryTokenStore()
	now := time.Now()

	expired := &IssuedToken{
		AccessToken: "expired-token",
		ShareID:     "share-expired",
		ClientID:    "client-a",
		IssuedAt:    now.Add(-2 * time.Hour),
		ExpiresAt:   now.Add(-time.Hour),
	}
	live := &IssuedToken{
		AccessToken: "live-token",
		ShareID:     "share-live",
		ClientID:    "client-b",
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Hour),
	}

	if err := store.Store(ctx, expired); err != nil {
		t.Fatalf("Store(expired): %v", err)
	}

	if err := store.Store(ctx, live); err != nil {
		t.Fatalf("Store(live): %v", err)
	}

	if err := store.CleanExpired(ctx); err != nil {
		t.Fatalf("CleanExpired: %v", err)
	}

	_, err := store.Get(ctx, expired.AccessToken)
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("Get(expired) = %v, want ErrTokenNotFound after CleanExpired", err)
	}

	got, err := store.Get(ctx, live.AccessToken)
	if err != nil {
		t.Fatalf("Get(live): %v", err)
	}

	if got.ShareID != live.ShareID {
		t.Errorf("Get(live).ShareID = %q, want %q", got.ShareID, live.ShareID)
	}
}
