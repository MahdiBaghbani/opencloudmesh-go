// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const maxStartBodyBytes = 4096

// Handler serves plane-A passive validator session endpoints.
type Handler struct {
	store            *validatorcore.Core
	probe            *ProbeRunner
	log              *slog.Logger
	caps             catalog.Caps
	externalBasePath string
	receiverMu       sync.Mutex
	parties          identity.PartyRepo
	receiverRealm    string
	receiverEmail    string
	receiverName     string
	// afterRetentionPatchReady is a test-only interleave after the PATCH
	// unlocked pre-check and before the guarded UPDATE.
	afterRetentionPatchReady func()
	// afterRetentionLockReady is a test-only interleave after the POST lock
	// snapshot and before the CAS lock UPDATE.
	afterRetentionLockReady func()
}

// NewHandler returns a passive validator HTTP handler.
func NewHandler(store *validatorcore.Core, log *slog.Logger) *Handler {
	return NewHandlerWithDeps(ProbeDeps{Store: store, Log: log})
}

// NewHandlerWithDiscovery returns a passive handler with optional discovery fetch wiring.
func NewHandlerWithDiscovery(
	store *validatorcore.Core,
	discoveryClient DiscoveryFetcher,
	log *slog.Logger,
) *Handler {
	return NewHandlerWithDeps(ProbeDeps{
		Store:     store,
		Discovery: discoveryClient,
		Log:       log,
	})
}

// NewHandlerWithDeps returns a passive handler with full probe wiring.
func NewHandlerWithDeps(deps ProbeDeps) *Handler {
	log := logutil.NoopIfNil(deps.Log)

	h := &Handler{
		store: deps.Store,
		probe: NewProbeRunnerWithDeps(deps),
		log:   log,
	}
	h.bindPromoteFollowUp()

	return h
}

// SetCaps records the capability set used for mount, advertisement, and
// fail-closed active extension.
func (h *Handler) SetCaps(caps catalog.Caps) {
	if h == nil {
		return
	}

	h.caps = caps
	if h.probe != nil {
		h.probe.canExtend = func() bool { return h.caps.ReverseInviteAvailable() }
	}
}

// Caps returns the capability set bound to this handler.
func (h *Handler) Caps() catalog.Caps {
	if h == nil {
		return catalog.Caps{}
	}

	return h.caps
}

type startCreateResponse struct {
	ID             string `json:"id"`
	OptInStats     bool   `json:"optInStats"`
	OptInPermanent bool   `json:"optInPermanent"`
}

type sessionPollResponse struct {
	State           string `json:"state"`
	Ts              int64  `json:"ts"`
	NextInstruction string `json:"nextInstruction,omitempty"`
	FailModeLabel   string `json:"failModeLabel,omitempty"`
}

// HandleStart serves POST /start for passive-core session creation.
func (h *Handler) HandleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	body, err := readLimitedBody(w, h.log, r, maxStartBodyBytes)
	if err != nil {
		return
	}

	req, decodeErr := decodeStartBody(r.Header.Get("Content-Type"), body)
	if decodeErr != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "invalid request body")

		return
	}

	hasTarget := strings.TrimSpace(req.Target) != ""
	hasID := strings.TrimSpace(req.ID) != ""

	if hasTarget && hasID {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "request body must be target or id, not both")

		return
	}

	if hasID && optInKeysPresent(req) {
		writeJSONError(
			w,
			h.log,
			http.StatusBadRequest,
			codeOptInCreateOnly,
			"opt-in fields are write-once at create",
		)

		return
	}

	if !hasTarget {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "request body requires target")

		return
	}

	h.handleCreateSession(
		w,
		r,
		strings.TrimSpace(req.Target),
		startConsent(req, validatorcore.OptInChannelStart),
	)
}

// HandleScan serves GET /api/scan for passive-core session creation with optional
// statistics contribute opt-in via the contribute query parameter and optional
// permanent report opt-in via the permanent query parameter.
func (h *Handler) HandleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", "target query parameter is required")

		return
	}

	opt := sessionOptIn{
		Stats:     ParseContribute(r.URL.Query().Get("contribute")),
		Permanent: ParsePermanent(r.URL.Query().Get("permanent")),
		Channel:   validatorcore.OptInChannelScan,
	}
	h.handleCreateSession(w, r, target, opt)
}

// HandleSession serves GET /api/session/{id} for anonymous session polling.
func (h *Handler) HandleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	if h.store == nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "store_unavailable", "validator store is not configured")

		return
	}

	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

		return
	}

	row, err := h.store.GetTestRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			writeJSONError(w, h.log, http.StatusNotFound, validatorcore.CodeSessionNotFound, "session not found")

			return
		}

		writeStoreError(w, h.log, err)

		return
	}

	row = h.refreshReadyWaiter(r.Context(), row)

	writeJSON(w, h.log, http.StatusOK, sessionPollResponse{
		State:           row.State,
		Ts:              row.UpdatedAt,
		NextInstruction: validatorcore.NextInstructionForRun(row),
		FailModeLabel:   validatorcore.TerminalReasonLabel(row.State, terminalReasonOf(row)),
	})
}

func terminalReasonOf(row *validatorcore.TestRun) string {
	if row == nil || row.TerminalReason == nil {
		return ""
	}

	return *row.TerminalReason
}

func (h *Handler) handleCreateSession(
	w http.ResponseWriter,
	r *http.Request,
	target string,
	opt sessionOptIn,
) {
	if opt.Active && !h.caps.ReverseInviteAvailable() {
		writeJSONError(w, h.log, http.StatusBadRequest, codeOptInActiveUnavailable, msgOptInActiveUnavailable)

		return
	}

	parsed, err := parseTarget(target)
	if err != nil {
		writeJSONError(w, h.log, http.StatusBadRequest, "invalid_request", targetClientMessage(err))

		return
	}

	testRunID, err := identity.UUIDv7()
	if err != nil {
		writeJSONError(w, h.log, http.StatusInternalServerError, "id_generation_failed", "failed to mint session id")

		return
	}

	now := time.Now().Unix()
	row := &validatorcore.TestRun{
		TestRunID:    testRunID,
		IsActive:     false,
		State:        validatorcore.StateCreated,
		TargetOrigin: parsed.origin,
		TargetHost:   parsed.targetHost,
		RemoteOCMID:  parsed.remoteOCMID,
		DiscoveryURL: strings.TrimSuffix(parsed.origin, "/") + "/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	applyCreateConsent(row, opt, now)

	ctx := r.Context()

	if err := h.store.CreatePassiveSession(ctx, row); err != nil {
		writeStoreError(w, h.log, err)

		return
	}

	h.probe.StartAsync(context.WithoutCancel(ctx), testRunID)

	writeJSON(w, h.log, http.StatusCreated, startCreateResponse{
		ID:             testRunID,
		OptInStats:     opt.Stats,
		OptInPermanent: opt.Permanent,
	})
}

func (h *Handler) refreshReadyWaiter(ctx context.Context, row *validatorcore.TestRun) *validatorcore.TestRun {
	if h == nil || row == nil || !validatorcore.IsReadyOptInWaiter(row) {
		return row
	}

	if err := h.promoteReadyWaiter(ctx, row.TestRunID); err != nil {
		h.log.Warn("session poll promote failed", "test_run_id", row.TestRunID, "error", err)
	}

	reloaded, err := h.store.GetTestRun(ctx, row.TestRunID)
	if err != nil {
		h.log.Warn("session poll reload failed", "test_run_id", row.TestRunID, "error", err)

		return row
	}

	return reloaded
}

func (h *Handler) promoteReadyWaiter(ctx context.Context, testRunID string) error {
	if h != nil && h.probe != nil {
		return h.probe.promoteOrWait(ctx, testRunID)
	}

	if h == nil || h.store == nil || !h.caps.ReverseInviteAvailable() {
		return nil
	}

	err := h.store.ExtendToActive(ctx, testRunID)
	if err == nil || validatorcore.IsActiveSlotBusy(err) {
		return nil
	}

	return fmt.Errorf("passive: promote ready waiter: %w", err)
}

func readLimitedBody(w http.ResponseWriter, log *slog.Logger, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, log, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")

			return nil, fmt.Errorf("read request body: %w", err)
		}

		writeJSONError(w, log, http.StatusBadRequest, "invalid_request", "invalid request body")

		return nil, fmt.Errorf("read request body: %w", err)
	}

	return body, nil
}

func writeStoreError(w http.ResponseWriter, log *slog.Logger, err error) {
	var storeErr *validatorcore.StoreError
	if errors.As(err, &storeErr) {
		switch storeErr.Op {
		case validatorcore.OpCreateSessionInsert:
			writeJSONError(w, log, http.StatusInternalServerError, "session_create_failed", "failed to create session")
		default:
			writeJSONError(w, log, http.StatusInternalServerError, "store_error", "validator store error")
		}

		return
	}

	switch {
	case errors.Is(err, validatorcore.ErrInFlightPassiveLimit):
		writeJSONError(
			w,
			log,
			http.StatusConflict,
			validatorcore.CodeInFlightPassiveLimit,
			"passive in-flight session limit reached",
		)
	case errors.Is(err, validatorcore.ErrSessionNotReady):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeSessionNotReady, "session is not ready")
	case errors.Is(err, validatorcore.ErrSessionNotFound):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeSessionNotFound, "session not found")
	case errors.Is(err, validatorcore.ErrStopSessionMiss):
		writeJSONError(w, log, http.StatusConflict, validatorcore.CodeStopSessionMiss, "stop did not match session state")
	default:
		writeJSONError(w, log, http.StatusInternalServerError, "store_error", "validator store error")
	}
}

func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, payload any) {
	log = logutil.NoopIfNil(log)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		log.Warn("failed to encode JSON response", "error", err)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Warn("failed to write JSON response", "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, log *slog.Logger, status int, code, message string) {
	writeJSON(w, log, status, map[string]string{
		"error":   code,
		"message": message,
	})
}
