// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// maxObservedBodyBytes bounds the request body read and the response capture
// so a large or streaming body can never grow the decorator's buffer.
const maxObservedBodyBytes = 64 << 10

// DecorateInviteAccepted wraps the product POST /ocm/invite-accepted handler
// with validator observation. The wrapped handler stays TestRun-unaware; the
// decorator only observes the protocol response and advances the active run.
// Decorator failures are logged and never change the protocol response.
func (s *Service) DecorateInviteAccepted(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The read is capped; one extra byte marks an oversized body, which is
		// rejected instead of being passed to the product handler truncated.
		reqBody, err := io.ReadAll(io.LimitReader(r.Body, maxObservedBodyBytes+1))
		if err != nil {
			s.log.Warn("reverseinvite: read invite-accepted request body", "error", err)
		}

		if len(reqBody) > maxObservedBodyBytes {
			api.WriteError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the 64 KiB limit")

			return
		}

		r.Body = io.NopCloser(bytes.NewReader(reqBody))

		cw := &observingWriter{ResponseWriter: w}
		next(cw, r)

		s.observeAccepted(r, reqBody, cw.status, cw.captured())
	}
}

// observeAccepted advances invite_minted -> invite_accepted when the protocol
// exchange matches the active run's bound outgoing invite exactly. Any
// mismatch or lookup failure skips the advance without disturbing the
// protocol response.
func (s *Service) observeAccepted(r *http.Request, reqBody []byte, status int, respBody []byte) {
	if status != http.StatusOK && status != http.StatusConflict {
		return
	}

	var req spec.InviteAcceptedRequest
	if err := json.Unmarshal(reqBody, &req); err != nil || req.Token == "" {
		return
	}

	// Only a 409 that still carries the sender identity body counts as an
	// acceptance observation; a plain 409 message does not.
	if status == http.StatusConflict && !decodableIdentity(respBody) {
		return
	}

	runID, shareWith, ok := s.matchAcceptedInvite(r.Context(), req.Token)
	if !ok {
		return
	}

	if err := s.deps.Store.RecordOutgoingInviteAccepted(r.Context(), runID, shareWith); err != nil {
		s.log.Warn("reverseinvite: record outgoing invite accepted", "error", err)
	}
}

// decodableIdentity reports whether a conflict response body still carries
// the sender identity.
func decodableIdentity(respBody []byte) bool {
	var resp spec.InviteAcceptedResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return false
	}

	return resp.UserID != ""
}

// matchAcceptedInvite loads the active run, the observed invite, and the
// correlation row, and reports the run ID and accepted user only when the
// exchange matches the run's bound outgoing invite exactly.
func (s *Service) matchAcceptedInvite(ctx context.Context, token string) (runID, shareWith string, ok bool) {
	runID, err := s.deps.Store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if err != nil {
		return "", "", false
	}

	run, err := s.deps.Store.GetTestRun(ctx, runID)
	if err != nil {
		return "", "", false
	}

	invite, err := s.deps.OutgoingInvites.GetByToken(ctx, token)
	if err != nil {
		return "", "", false
	}

	corr, err := s.deps.Store.GetShareCorrelation(ctx, runID, validatorcore.RoleOutgoingInvite, validatorcore.LocalIdentityA)
	if err != nil {
		return "", "", false
	}

	if corr.InviteID == nil || *corr.InviteID != invite.ID || corr.ProviderID != token {
		return "", "", false
	}

	if invite.CreatedByUserID != run.TestRunID {
		return "", "", false
	}

	if invite.AcceptedProviderFQDNNormalized == "" || invite.AcceptedProviderFQDNNormalized != run.TargetHost {
		return "", "", false
	}

	if invite.AcceptedUserID == "" {
		return "", "", false
	}

	return runID, invite.AcceptedUserID, true
}

// observingWriter captures status and a bounded body copy while passing every
// write through to the real response writer.
type observingWriter struct {
	http.ResponseWriter

	status int
	buf    bytes.Buffer
}

func (w *observingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *observingWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	// The capture is strictly capped: only the remaining budget is buffered,
	// while the full write always passes through to the real response.
	if remaining := maxObservedBodyBytes - w.buf.Len(); remaining > 0 {
		capture := p
		if len(capture) > remaining {
			capture = capture[:remaining]
		}

		// bytes.Buffer.Write is documented to never fail; if that ever
		// changed, surface it rather than silently dropping the capture.
		if _, err := w.buf.Write(capture); err != nil {
			return 0, fmt.Errorf("reverseinvite: capture response body: %w", err)
		}
	}

	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, fmt.Errorf("reverseinvite: write observed response: %w", err)
	}

	return n, nil
}

// Flush passes through so streaming handlers keep their flush semantics.
func (w *observingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *observingWriter) captured() []byte {
	return w.buf.Bytes()
}
