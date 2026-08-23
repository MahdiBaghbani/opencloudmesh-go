// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleStart_FourConsentCombinations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		body      map[string]any
		wantStats bool
		wantPerm  bool
	}{
		{
			name:      "neither omitted",
			body:      map[string]any{"target": "https://peer.example"},
			wantStats: false,
			wantPerm:  false,
		},
		{
			name: "stats only",
			body: map[string]any{
				"target":         "https://peer.example",
				"optInStats":     true,
				"optInPermanent": false,
			},
			wantStats: true,
			wantPerm:  false,
		},
		{
			name: "permanent only",
			body: map[string]any{
				"target":         "https://peer.example",
				"optInStats":     false,
				"optInPermanent": true,
			},
			wantStats: false,
			wantPerm:  true,
		},
		{
			name: "both",
			body: map[string]any{
				"target":         "https://peer.example",
				"optInStats":     true,
				"optInPermanent": true,
			},
			wantStats: true,
			wantPerm:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/start",
				bytes.NewReader(mustJSON(t, tc.body)),
			)
			rec := httptest.NewRecorder()
			h.HandleStart(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
			}

			created := decodeCreateEcho(t, rec)
			if created.OptInStats != tc.wantStats || created.OptInPermanent != tc.wantPerm {
				t.Fatalf("echo = %+v, want stats=%v permanent=%v", created, tc.wantStats, tc.wantPerm)
			}

			assertCreateConsentRow(
				t,
				store,
				created.ID,
				tc.wantStats,
				tc.wantPerm,
				validatorcore.OptInChannelStart,
			)
		})
	}
}

func TestHandleScan_QueryConsentPairs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		query     string
		wantStats bool
		wantPerm  bool
	}{
		{name: "neither", query: "target=https://peer.example", wantStats: false, wantPerm: false},
		{name: "stats only", query: "target=https://peer.example&contribute=1", wantStats: true, wantPerm: false},
		{name: "permanent only", query: "target=https://peer.example&permanent=1", wantStats: false, wantPerm: true},
		{name: "both", query: "target=https://peer.example&contribute=1&permanent=1", wantStats: true, wantPerm: true},
		{name: "contribute true stays off", query: "target=https://peer.example&contribute=true", wantStats: false, wantPerm: false},
		{name: "permanent yes stays off", query: "target=https://peer.example&permanent=yes", wantStats: false, wantPerm: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"/api/scan?"+tc.query,
				nil,
			)
			rec := httptest.NewRecorder()
			h.HandleScan(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
			}

			created := decodeCreateEcho(t, rec)
			if created.OptInStats != tc.wantStats || created.OptInPermanent != tc.wantPerm {
				t.Fatalf("echo = %+v, want stats=%v permanent=%v", created, tc.wantStats, tc.wantPerm)
			}

			assertCreateConsentRow(
				t,
				store,
				created.ID,
				tc.wantStats,
				tc.wantPerm,
				validatorcore.OptInChannelScan,
			)
		})
	}
}

func TestHandleStart_UnknownContributeField(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	body := mustJSON(t, map[string]any{
		"target":     "https://peer.example",
		"contribute": true,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	assertJSONError(t, rec, "invalid_request")
}

func TestHandleStart_InvalidOptInValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{name: "stats number", body: `{"target":"https://peer.example","optInStats":1}`},
		{name: "stats string", body: `{"target":"https://peer.example","optInStats":"true"}`},
		{name: "stats null", body: `{"target":"https://peer.example","optInStats":null}`},
		{name: "permanent string", body: `{"target":"https://peer.example","optInPermanent":"1"}`},
		{name: "permanent null", body: `{"target":"https://peer.example","optInPermanent":null}`},
		{name: "active string", body: `{"target":"https://peer.example","optInActive":"true"}`},
		{name: "active null", body: `{"target":"https://peer.example","optInActive":null}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := NewHandler(openHandlerTestStore(t), nil)
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/start",
				bytes.NewReader([]byte(tc.body)),
			)
			rec := httptest.NewRecorder()
			h.HandleStart(rec, req)

			assertJSONError(t, rec, "invalid_request")
		})
	}
}

func TestHandleStart_FormURLEncodedOptInActiveBooleans(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		optInActive string
		wantStatus  int
		wantError   string
		wantActive  bool
	}{
		{
			name:        "canonical true",
			optInActive: "true",
			wantStatus:  http.StatusCreated,
			wantActive:  true,
		},
		{
			name:        "canonical false",
			optInActive: "false",
			wantStatus:  http.StatusCreated,
			wantActive:  false,
		},
		{
			name:        "noncanonical 1",
			optInActive: "1",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "noncanonical yes",
			optInActive: "yes",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
		{
			name:        "noncanonical on",
			optInActive: "on",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid_request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			allowActiveExtend(h)

			form := url.Values{}
			form.Set("target", "https://peer.example")
			form.Set("optInActive", tc.optInActive)

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/start",
				strings.NewReader(form.Encode()),
			)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			h.HandleStart(rec, req)

			if tc.wantError != "" {
				assertJSONError(t, rec, tc.wantError)

				return
			}

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}

			created := decodeCreateEcho(t, rec)

			row, err := store.GetTestRun(t.Context(), created.ID)
			if err != nil {
				t.Fatalf("GetTestRun: %v", err)
			}

			if row.OptInActive != tc.wantActive {
				t.Fatalf("optInActive = %v, want %v", row.OptInActive, tc.wantActive)
			}
		})
	}
}

func TestHandleStart_OptInCreateOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body map[string]any
	}{
		{name: "stats true", body: map[string]any{"id": "run-extend", "optInStats": true}},
		{name: "permanent false present", body: map[string]any{"id": "run-extend", "optInPermanent": false}},
		{name: "active true", body: map[string]any{"id": "run-extend", "optInActive": true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := NewHandler(openHandlerTestStore(t), nil)
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/start",
				bytes.NewReader(mustJSON(t, tc.body)),
			)
			rec := httptest.NewRecorder()
			h.HandleStart(rec, req)

			assertJSONError(t, rec, codeOptInCreateOnly)
		})
	}
}

func TestHandleStart_OptInActivePersistsProvenance(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	allowActiveExtend(h)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]any{
			"target":      "https://peer.example",
			"optInActive": true,
		})),
	)
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
	}

	created := decodeCreateEcho(t, rec)

	row, err := store.GetTestRun(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !row.OptInActive {
		t.Fatal("opt_in_active unset")
	}

	assertConsentProvenance(
		t,
		"active",
		true,
		validatorcore.OptInChannelStart,
		row.OptInActiveChannel,
		row.OptInActiveAt,
	)
}

func TestHandleStart_OptInActiveRejectedWithoutCaps(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		caps catalog.Caps
	}{
		{name: "empty caps"},
		{name: "abort only", caps: catalog.Caps{Abort: true}},
		{
			name: "incomplete reverse invite",
			caps: catalog.Caps{Runner: true, ReverseInvite: true, ForwardShare: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := openHandlerTestStore(t)
			h := NewHandler(store, nil)
			h.SetCaps(tc.caps)

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/start",
				bytes.NewReader(mustJSON(t, map[string]any{
					"target":      "https://peer.example",
					"optInActive": true,
				})),
			)
			rec := httptest.NewRecorder()
			h.HandleStart(rec, req)

			assertJSONError(t, rec, codeOptInActiveUnavailable)

			count, err := store.CountInFlightPassive(t.Context())
			if err != nil {
				t.Fatalf("CountInFlightPassive: %v", err)
			}

			if count != 0 {
				t.Fatalf("in-flight sessions = %d, want 0 after rejected opt-in", count)
			}
		})
	}
}

func TestHandleScan_IgnoresOptInActiveQuery(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example&optInActive=1",
		nil,
	)
	rec := httptest.NewRecorder()
	h.HandleScan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
	}

	created := decodeCreateEcho(t, rec)
	assertCreateConsentRow(
		t,
		store,
		created.ID,
		false,
		false,
		validatorcore.OptInChannelScan,
	)
}

func TestHandleStart_CreateEchoIncludesFalseValues(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "https://peer.example"})),
	)
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, raw, []string{"id", "optInPermanent", "optInStats"})

	var stats bool
	if err := json.Unmarshal(raw["optInStats"], &stats); err != nil {
		t.Fatalf("optInStats: %v", err)
	}

	var permanent bool
	if err := json.Unmarshal(raw["optInPermanent"], &permanent); err != nil {
		t.Fatalf("optInPermanent: %v", err)
	}

	if stats || permanent {
		t.Fatalf("default echo stats=%v permanent=%v, want both false", stats, permanent)
	}
}

func decodeCreateEcho(t *testing.T, rec *httptest.ResponseRecorder) startCreateResponse {
	t.Helper()

	var created startCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty session id")
	}

	return created
}

func assertCreateConsentRow(
	t *testing.T,
	store *validatorcore.Core,
	runID string,
	wantStats, wantPerm bool,
	wantChannel string,
) {
	t.Helper()

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.OptInStats != wantStats || row.OptInPermanent != wantPerm {
		t.Fatalf(
			"row consents stats=%v permanent=%v, want %v/%v",
			row.OptInStats,
			row.OptInPermanent,
			wantStats,
			wantPerm,
		)
	}

	if row.OptInActive {
		t.Fatal("opt-in active must stay off on this create path")
	}

	assertConsentProvenance(t, "stats", wantStats, wantChannel, row.OptInStatsChannel, row.OptInStatsAt)
	assertConsentProvenance(t, "permanent", wantPerm, wantChannel, row.OptInPermanentChannel, row.OptInPermanentAt)
}

func assertConsentProvenance(
	t *testing.T,
	label string,
	selected bool,
	wantChannel string,
	channel *string,
	at *int64,
) {
	t.Helper()

	if !selected {
		if channel != nil || at != nil {
			t.Fatalf("%s provenance = (%v, %v), want both NULL", label, channel, at)
		}

		return
	}

	if channel == nil || *channel != wantChannel {
		t.Fatalf("%s channel = %v, want %q", label, channel, wantChannel)
	}

	if at == nil || *at <= 0 {
		t.Fatalf("%s timestamp = %v, want set", label, at)
	}
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if payload["error"] != code {
		t.Fatalf("error = %q, want %q", payload["error"], code)
	}
}
