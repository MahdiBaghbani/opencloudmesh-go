// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

type ctxObservingNotifier struct {
	ctxCh   chan context.Context
	release chan struct{}
	done    chan struct{}
}

func (n *ctxObservingNotifier) Notify(
	ctx context.Context,
	_ string,
	_ string,
	_ string,
	_ string,
	_ json.RawMessage,
) error {
	if n.ctxCh != nil {
		n.ctxCh <- ctx
	}

	if n.release != nil {
		<-n.release
	}

	if n.done != nil {
		close(n.done)
	}

	return nil
}

func TestNotifyShareStatusAsync_RequestCancelDoesNotCancelNotifierContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/inbox/shares/share-1/accept", nil)

	ctxCh := make(chan context.Context, 1)
	release := make(chan struct{})
	notifyDone := make(chan struct{})

	h := &Handler{
		notifier: &ctxObservingNotifier{
			ctxCh:   ctxCh,
			release: release,
			done:    notifyDone,
		},
		log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	h.notifyShareStatusAsync(req, "sender.example.com", "provider-ctx", "file", spec.NotificationTypeShareAccepted)

	observed := <-ctxCh

	cancel()

	select {
	case <-observed.Done():
		t.Fatal("notification context cancelled when request context was cancelled")
	default:
	}

	deadline, ok := observed.Deadline()
	if !ok {
		t.Fatal("expected deadline on notification context")
	}

	remaining := time.Until(deadline)
	if remaining < 29*time.Second || remaining > notifyTimeout {
		t.Fatalf("deadline remaining = %v, want about %v", remaining, notifyTimeout)
	}

	close(release)

	select {
	case <-notifyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async notification to finish")
	}
}
