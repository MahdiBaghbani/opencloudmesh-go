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
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/identitybind"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	// maxObservedBodyBytes bounds the request body read and the response
	// capture so a large or streaming body can never grow the decorator's
	// buffer.
	maxObservedBodyBytes = 64 << 10

	evidenceReasonAccepterUnenforceable = "accepter_user_unenforceable"
	evidenceStepInviteAccepted          = "invite_accepted"
)

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

		if err := s.observeAccepted(r, reqBody, cw.status, cw.captured()); err != nil {
			s.log.Error("reverseinvite: observe invite-accepted", "error", err)
		}
	}
}

// observeAccepted advances invite_minted -> invite_accepted when the protocol
// exchange matches the active run's bound outgoing invite exactly. Evidence
// must persist before the run advances; a persist failure is returned so the
// caller can surface it and a later request can retry. Mismatch or lookup
// failures skip without disturbing the protocol response.
func (s *Service) observeAccepted(r *http.Request, reqBody []byte, status int, respBody []byte) error {
	if status != http.StatusOK && status != http.StatusConflict {
		return nil
	}

	token, ok := inviteAcceptedToken(reqBody)
	if !ok {
		return nil
	}

	// Only a 409 that still carries the sender identity body counts as an
	// acceptance observation; a plain 409 message does not.
	if status == http.StatusConflict && !decodableIdentity(respBody) {
		return nil
	}

	match, ok := s.correlateAcceptedInvite(r.Context(), token)
	if !ok {
		return nil
	}

	if match.run.State == validatorcore.StateInviteMinted {
		bound, bindErr := s.bindAcceptedIdentity(r.Context(), match)
		if bindErr != nil {
			return bindErr
		}

		if !bound {
			return nil
		}
	}

	if err := s.recordIncomingInviteAccepted(r.Context(), match.run.TestRunID, status); err != nil {
		return err
	}

	if err := s.deps.Store.RecordOutgoingInviteAccepted(
		r.Context(),
		match.run.TestRunID,
		match.invite.AcceptedUserID,
	); err != nil {
		return fmt.Errorf("reverseinvite: record outgoing invite accepted: %w", err)
	}

	return nil
}

func (s *Service) recordIncomingInviteAccepted(ctx context.Context, runID string, status int) error {
	if s.recordAccepted != nil {
		return s.recordAccepted(ctx, runID, status)
	}

	if err := s.deps.Store.PersistActiveExchangeAndFact(
		ctx,
		validatorcore.IncomingInviteAcceptedExchange(runID, status),
		validatorcore.OutgoingInviteAcceptedFact(runID, nil),
	); err != nil {
		return fmt.Errorf("reverseinvite: record incoming invite-accepted: %w", err)
	}

	return nil
}

// inviteAcceptedToken reports the request token when the body is a usable
// invite-accepted payload.
func inviteAcceptedToken(reqBody []byte) (string, bool) {
	var req spec.InviteAcceptedRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return "", false
	}

	if req.Token == "" {
		return "", false
	}

	return req.Token, true
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

// acceptedInviteMatch is the correlated outgoing invite for one observation.
type acceptedInviteMatch struct {
	run    *validatorcore.TestRun
	invite *invitesoutgoing.OutgoingInvite
}

// correlateAcceptedInvite loads the active run and the observed invite and
// reports them only when the pointer, creator, and token match and the
// accepted user and host fields are present. It does not bind identity or
// pin designated_share_with.
func (s *Service) correlateAcceptedInvite(ctx context.Context, token string) (acceptedInviteMatch, bool) {
	var none acceptedInviteMatch

	runID, err := s.deps.Store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if err != nil {
		return none, false
	}

	run, err := s.deps.Store.GetTestRun(ctx, runID)
	if err != nil {
		return none, false
	}

	invite, err := s.deps.OutgoingInvites.GetByToken(ctx, token)
	if err != nil {
		return none, false
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID != invite.ID {
		return none, false
	}

	if invite.CreatedByUserID != run.TestRunID {
		return none, false
	}

	if invite.AcceptedProviderFQDN == "" || invite.AcceptedUserID == "" {
		return none, false
	}

	return acceptedInviteMatch{run: run, invite: invite}, true
}

// bindAcceptedIdentity compares the composed incoming accepter identity to
// the session starter. Wrong host or a plain local-user mismatch hard-fails
// the run without pinning. Opaque or UUID users warn and continue. A bare
// URL start enforces host only.
func (s *Service) bindAcceptedIdentity(ctx context.Context, match acceptedInviteMatch) (bool, error) {
	scheme := schemeFromOrigin(match.run.TargetOrigin, s.deps.LocalIdentity.Scheme)

	incoming, err := identitybind.Canonicalize(composeAcceptedIdentity(match.invite), scheme)
	if err != nil {
		s.log.Warn("reverseinvite: canonicalize accepted identity", "error", err)

		return false, nil
	}

	if incoming.Provider != match.run.TargetHost {
		return false, s.haltWrongAccepter(ctx, match.run.TestRunID)
	}

	if match.run.StarterOCMID == nil || *match.run.StarterOCMID == "" {
		return true, nil
	}

	starter, err := identitybind.Canonicalize(*match.run.StarterOCMID, scheme)
	if err != nil {
		s.log.Warn("reverseinvite: canonicalize starter identity", "error", err)

		return false, nil
	}

	decision := identitybind.Compare(starter, incoming)
	if !decision.HostsEqual {
		return false, s.haltWrongAccepter(ctx, match.run.TestRunID)
	}

	if decision.UserEnforceable && !decision.UsersEqual {
		return false, s.haltWrongAccepter(ctx, match.run.TestRunID)
	}

	if !decision.UserEnforceable {
		if warnErr := s.warnUnenforceableAccepter(ctx, match.run.TestRunID); warnErr != nil {
			return false, warnErr
		}
	}

	return true, nil
}

func composeAcceptedIdentity(invite *invitesoutgoing.OutgoingInvite) string {
	return invite.AcceptedUserID + "@" + invite.AcceptedProviderFQDN
}

func schemeFromOrigin(origin, fallback string) string {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" {
		return fallback
	}

	return strings.ToLower(parsed.Scheme)
}

func (s *Service) haltWrongAccepter(ctx context.Context, runID string) error {
	if err := s.deps.Store.ReleaseActiveHardFail(ctx, runID, validatorcore.ReasonWrongAccepter); err != nil {
		return fmt.Errorf("reverseinvite: hard-fail wrong accepter: %w", err)
	}

	return nil
}

func (s *Service) warnUnenforceableAccepter(ctx context.Context, runID string) error {
	err := s.deps.Store.ApplyEvidenceFact(ctx, validatorcore.ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         validatorcore.SpecificationAreaSharing,
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonAccepterUnenforceable,
		Severity:     validatorcore.GradeWarn,
		AffectsGrade: true,
		Leg:          validatorcore.EvidenceLegForward,
	})
	if err != nil {
		return fmt.Errorf("reverseinvite: record unenforceable accepter: %w", err)
	}

	return nil
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
