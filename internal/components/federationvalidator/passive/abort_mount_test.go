// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleAbort_UnknownID404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	rec := postAbort(t, h, "missing-run", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 body %s", rec.Code, rec.Body.String())
	}

	payload := decodeAbortError(t, rec)
	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleAbort_InvalidJSONBodyUsesURLID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-body"

	seedAbortRun(t, store, runID, true, validatorcore.StateForwardShareSent)
	decodeAbortOK(t, postAbort(t, h, runID, []byte("{not-json")), runID)
	assertPersistedOperatorAbort(t, loadAbortRun(t, store, runID))
}

func TestHandleAbort_DirectGETMethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/abort", nil)
	rec := httptest.NewRecorder()
	h.HandleAbort(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleAbort_MountedGETAndSuffix(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/abort", nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)

	if getRec.Code == http.StatusOK {
		t.Fatal("mounted GET abort must not succeed")
	}

	extraReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/run-1/abort/extra", nil)
	extraRec := httptest.NewRecorder()
	r.ServeHTTP(extraRec, extraReq)

	if extraRec.Code != http.StatusNotFound {
		t.Fatalf("suffix status = %d, want 404", extraRec.Code)
	}
}

func TestHandleAbort_ConcurrentSecondMissDoesNotRewrite(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-http-abort-race"

	seedAbortRun(t, store, runID, true, validatorcore.StateActiveRunning)

	results := make([]*httptest.ResponseRecorder, 2)

	var wg sync.WaitGroup

	for i := range results {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			results[i] = postAbort(t, h, runID, nil)
		}(i)
	}

	wg.Wait()

	var okCount, missCount int

	for _, rec := range results {
		switch rec.Code {
		case http.StatusOK:
			okCount++
		case http.StatusConflict:
			missCount++

			payload := decodeAbortError(t, rec)
			if payload["error"] != validatorcore.CodeAbortSessionMiss {
				t.Fatalf("raced miss error = %q, want %q", payload["error"], validatorcore.CodeAbortSessionMiss)
			}
		case http.StatusGone:
			t.Fatal("raced abort must not return 410")
		default:
			t.Fatalf("raced status = %d body %s", rec.Code, rec.Body.String())
		}
	}

	if okCount != 1 || missCount != 1 {
		t.Fatalf("raced outcomes ok=%d miss=%d, want 1 and 1", okCount, missCount)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StateTerminalFail {
		t.Fatalf("is_active=%v state=%q, want one terminal_fail write", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != validatorcore.ReasonOperatorAborted {
		t.Fatalf("terminal_reason = %v, want %q", got.TerminalReason, validatorcore.ReasonOperatorAborted)
	}
}

func TestMountPlaneARoutes_AbortIsPostOnly(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	routes, err := EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	var abortPosts, abortGets int

	for _, route := range routes {
		if !strings.HasSuffix(route.FullPath, "/api/session/{id}/abort") {
			continue
		}

		switch route.Method {
		case http.MethodPost:
			abortPosts++
		case http.MethodGet:
			abortGets++
		}
	}

	if abortPosts != 1 {
		t.Fatalf("POST abort routes = %d, want 1", abortPosts)
	}

	if abortGets != 0 {
		t.Fatalf("GET abort routes = %d, want 0", abortGets)
	}
}

func TestAbortSource_UsesHardFailWriter(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("abort.go")
	if err != nil {
		t.Fatalf("read abort.go: %v", err)
	}

	text := string(src)
	if !strings.Contains(text, "ReleaseActiveHardFail") {
		t.Fatal("abort handler must call ReleaseActiveHardFail")
	}

	if !strings.Contains(text, "ReasonOperatorAborted") {
		t.Fatal("abort handler must pass ReasonOperatorAborted")
	}

	for _, banned := range []string{
		"StateInterrupted",
		"FlipLateReverseShareToPass",
		"ReasonReverseShareTimeout",
		"interrupted",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("abort.go must not mention %q", banned)
		}
	}
}

func TestOperatorAborted_NotUsedByActiveRunner(t *testing.T) {
	t.Parallel()

	err := filepath.WalkDir("../active", func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // test walks the local active tree
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}

		if bytes.Contains(data, []byte("operator_aborted")) ||
			bytes.Contains(data, []byte("ReasonOperatorAborted")) {
			t.Errorf("%s uses operator abort reason", path)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk active tree: %v", err)
	}
}
