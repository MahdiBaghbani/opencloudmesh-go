// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

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
