// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// ReverseWaitOpener opens the event-driven reverse-share wait for a session
// the poll path loaded while it is still in the capability exercise. The
// validator wires it from the active reverse-share leg; a nil opener keeps
// the poll a plain read.
type ReverseWaitOpener func(ctx context.Context, testRunID string) error

// healReverseWaitOnPoll wraps the session poll so a session still in the
// capability exercise re-enters the reverse-share wait open before the poll
// answers, letting a wait that failed to open in the exercise request
// self-heal on the next poll. Best-effort: an open failure only logs, and the
// inner poll re-reads the row so the response carries the state the open left
// behind. The wrapper never changes the poll DTO or its error responses.
func healReverseWaitOnPoll(
	store *validatorcore.Core,
	log *slog.Logger,
	opener ReverseWaitOpener,
	next http.HandlerFunc,
) http.HandlerFunc {
	log = logutil.NoopIfNil(log)

	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(chi.URLParam(r, "id"))

		if store == nil || id == "" {
			next(w, r)

			return
		}

		ctx := r.Context()

		row, err := store.GetTestRun(ctx, id)
		if err != nil {
			// The inner poll serves the canonical not-found/store error.
			next(w, r)

			return
		}

		if row.IsActive && row.State == validatorcore.StateCapabilityExercise {
			if openErr := opener(ctx, id); openErr != nil {
				log.Warn("reverse-share wait heal failed", "session", id, "error", openErr)
			}
		}

		next(w, r)
	}
}
