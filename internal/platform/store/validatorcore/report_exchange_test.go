// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

// allTestRunIDs tells count helpers to skip the test_run_id filter.
const allTestRunIDs = ""

func openMigratedProductionCore(t *testing.T) *Core {
	t.Helper()

	sqlCore := openPeerStore(t)
	db := sqlCore.DB()

	if err := MigrateModels(db); err != nil {
		t.Fatalf("MigrateModels: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql handle: %v", err)
	}

	sqlDB.SetMaxOpenConns(4)

	requireForeignKeysOn(t, db)

	return NewCore(db)
}

func newMinimalExchange(runID string) *ReportExchange {
	return &ReportExchange{
		TestRunID:  runID,
		CapturedAt: 1,
		Direction:  "out",
		EndpointID: "discovery",
		Method:     "GET",
		URL:        "https://t.example/ocm",
		CreatedAt:  1,
	}
}

func countReportExchanges(t *testing.T, core *Core, runID string) int64 {
	t.Helper()

	return countByTestRunID(t, core.DB(), &ReportExchange{}, runID, "report_exchange")
}

func countByTestRunID(t *testing.T, db *gorm.DB, model any, runID, label string) int64 {
	t.Helper()

	var n int64

	q := db.Model(model)
	if runID != allTestRunIDs {
		q = q.Where("test_run_id = ?", runID)
	}

	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", label, err)
	}

	return n
}

func TestInsertReportExchange_WritesFullColumnSet(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-full-columns"
	createTestRun(t, core.DB(), runID)

	started := int64(10)
	ended := int64(20)
	duration := int64(10)
	actor := "validator"
	identity := LocalIdentityA
	corrRole := RoleOutgoingToTarget
	leg := "forward"
	host := "t.example"
	status := 200
	httpVer := "HTTP/1.1"
	errText := "none"
	reqID := "req-full"
	reqHdr := `{"accept":"application/json"}`
	respHdr := `{"content-type":"application/json"}`
	sigRaw := "sig"
	sigKey := "key-1"
	sigAlg := "ed25519"
	sigScheme := "httpsig"
	sigValid := true
	digest := "SHA-256=abc"
	reqRed := `{"token":"[redacted]"}`
	respRed := `{"secret":"[redacted]"}`
	reqHash := "aa"
	respHash := "bb"
	reqBytes := int64(2)
	respBytes := int64(2)

	row := &ReportExchange{
		TestRunID:         runID,
		CapturedAt:        15,
		StartedAt:         &started,
		EndedAt:           &ended,
		DurationMs:        &duration,
		Direction:         "out",
		Actor:             &actor,
		LocalIdentity:     &identity,
		CorrRole:          &corrRole,
		Leg:               &leg,
		EndpointID:        "discovery",
		Method:            "GET",
		URL:               "https://t.example/ocm",
		Host:              &host,
		StatusCode:        &status,
		HTTPVersion:       &httpVer,
		ErrorText:         &errText,
		RequestID:         &reqID,
		ReqHeadersJSON:    &reqHdr,
		RespHeadersJSON:   &respHdr,
		SigRaw:            &sigRaw,
		SigKeyID:          &sigKey,
		SigAlgorithm:      &sigAlg,
		SigScheme:         &sigScheme,
		SigValid:          &sigValid,
		Digest:            &digest,
		ReqBodyRedacted:   &reqRed,
		RespBodyRedacted:  &respRed,
		ReqBodySHA256:     &reqHash,
		RespBodySHA256:    &respHash,
		ReqBodyBytes:      &reqBytes,
		RespBodyBytes:     &respBytes,
		ReqBodyTruncated:  true,
		RespBodyTruncated: true,
		CreatedAt:         15,
	}

	if err := core.InsertReportExchange(ctx, row); err != nil {
		t.Fatalf("InsertReportExchange: %v", err)
	}

	if row.ExchangeID == 0 {
		t.Fatal("expected exchange_id to be assigned")
	}

	if row.Seq != 1 {
		t.Fatalf("seq = %d, want 1", row.Seq)
	}

	var stored ReportExchange
	if err := core.DB().WithContext(ctx).First(&stored, "exchange_id = ?", row.ExchangeID).Error; err != nil {
		t.Fatalf("load exchange: %v", err)
	}

	assertFullExchangeRoundTrip(t, &stored, row)
}

func assertFullExchangeRoundTrip(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	assertExchangeIdentity(t, got, want)
	assertExchangeRouting(t, got, want)
	assertExchangeHTTP(t, got, want)
	assertExchangeSignature(t, got, want)
	assertExchangeBodies(t, got, want)
}

func assertExchangeIdentity(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	if got.TestRunID != want.TestRunID || got.Seq != want.Seq || got.CapturedAt != want.CapturedAt {
		t.Fatalf("identity columns = %+v, want test_run_id/seq/captured_at from input", got)
	}

	if got.CreatedAt != want.CreatedAt {
		t.Fatalf("created_at = %d, want %d", got.CreatedAt, want.CreatedAt)
	}

	if deref(got.StartedAt) != deref(want.StartedAt) ||
		deref(got.EndedAt) != deref(want.EndedAt) ||
		deref(got.DurationMs) != deref(want.DurationMs) {
		t.Fatalf("timing columns = started=%v ended=%v duration=%v", got.StartedAt, got.EndedAt, got.DurationMs)
	}
}

func assertExchangeRouting(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	if got.Direction != want.Direction ||
		deref(got.Actor) != deref(want.Actor) ||
		deref(got.LocalIdentity) != deref(want.LocalIdentity) ||
		deref(got.CorrRole) != deref(want.CorrRole) ||
		deref(got.Leg) != deref(want.Leg) {
		t.Fatalf("routing columns mismatch: %+v", got)
	}

	if got.EndpointID != want.EndpointID || got.Method != want.Method || got.URL != want.URL {
		t.Fatalf("request line = %s %s %s", got.Method, got.EndpointID, got.URL)
	}
}

func assertExchangeHTTP(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	if deref(got.Host) != deref(want.Host) ||
		deref(got.StatusCode) != deref(want.StatusCode) ||
		deref(got.HTTPVersion) != deref(want.HTTPVersion) ||
		deref(got.ErrorText) != deref(want.ErrorText) ||
		deref(got.RequestID) != deref(want.RequestID) {
		t.Fatalf("http metadata mismatch: %+v", got)
	}

	if deref(got.ReqHeadersJSON) != deref(want.ReqHeadersJSON) ||
		deref(got.RespHeadersJSON) != deref(want.RespHeadersJSON) {
		t.Fatalf("headers mismatch req=%v resp=%v", got.ReqHeadersJSON, got.RespHeadersJSON)
	}
}

func assertExchangeSignature(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	if deref(got.SigRaw) != deref(want.SigRaw) ||
		deref(got.SigKeyID) != deref(want.SigKeyID) ||
		deref(got.SigAlgorithm) != deref(want.SigAlgorithm) ||
		deref(got.SigScheme) != deref(want.SigScheme) ||
		deref(got.SigValid) != deref(want.SigValid) ||
		deref(got.Digest) != deref(want.Digest) {
		t.Fatalf("signature columns mismatch: %+v", got)
	}
}

func assertExchangeBodies(t *testing.T, got, want *ReportExchange) {
	t.Helper()

	if deref(got.ReqBodyRedacted) != deref(want.ReqBodyRedacted) ||
		deref(got.RespBodyRedacted) != deref(want.RespBodyRedacted) ||
		deref(got.ReqBodySHA256) != deref(want.ReqBodySHA256) ||
		deref(got.RespBodySHA256) != deref(want.RespBodySHA256) ||
		deref(got.ReqBodyBytes) != deref(want.ReqBodyBytes) ||
		deref(got.RespBodyBytes) != deref(want.RespBodyBytes) ||
		got.ReqBodyTruncated != want.ReqBodyTruncated ||
		got.RespBodyTruncated != want.RespBodyTruncated {
		t.Fatalf("body columns mismatch")
	}
}

func deref[T comparable](v *T) T {
	var zero T
	if v == nil {
		return zero
	}

	return *v
}

func TestInsertReportExchange_AllocatesSeqPerRun(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	createTestRun(t, core.DB(), "run-seq-a")
	createTestRun(t, core.DB(), "run-seq-b")

	first := newMinimalExchange("run-seq-a")
	second := newMinimalExchange("run-seq-a")
	other := newMinimalExchange("run-seq-b")

	if err := core.InsertReportExchange(ctx, first); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	if err := core.InsertReportExchange(ctx, second); err != nil {
		t.Fatalf("second insert: %v", err)
	}

	if err := core.InsertReportExchange(ctx, other); err != nil {
		t.Fatalf("other-run insert: %v", err)
	}

	if first.Seq != 1 || second.Seq != 2 {
		t.Fatalf("run-seq-a seqs = %d,%d, want 1,2", first.Seq, second.Seq)
	}

	if other.Seq != 1 {
		t.Fatalf("run-seq-b seq = %d, want 1", other.Seq)
	}
}

func TestInsertReportExchange_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()

		if err := (*Core)(nil).InsertReportExchange(t.Context(), newMinimalExchange("run")); err == nil {
			t.Fatal("expected error for nil store")
		}
	})

	t.Run("nil row", func(t *testing.T) {
		t.Parallel()

		core := openMigratedProductionCore(t)

		err := core.InsertReportExchange(t.Context(), nil)
		if err == nil {
			t.Fatal("expected error for nil row")
		}

		if err.Error() != "validatorcore: nil report exchange" {
			t.Fatalf("nil row error = %v, want validatorcore: nil report exchange", err)
		}

		var storeErr *StoreError
		if errors.As(err, &storeErr) {
			t.Fatal("invalid input must be rejected before store insert")
		}
	})

	tests := []struct {
		name    string
		mutate  func(*ReportExchange)
		wantErr string
	}{
		{
			name:    "empty test_run_id",
			mutate:  func(row *ReportExchange) { row.TestRunID = "" },
			wantErr: "validatorcore: empty test_run_id",
		},
		{
			name:    "empty direction",
			mutate:  func(row *ReportExchange) { row.Direction = "" },
			wantErr: "validatorcore: empty direction",
		},
		{
			name:    "empty endpoint_id",
			mutate:  func(row *ReportExchange) { row.EndpointID = "" },
			wantErr: "validatorcore: empty endpoint_id",
		},
		{
			name:    "empty method",
			mutate:  func(row *ReportExchange) { row.Method = "" },
			wantErr: "validatorcore: empty method",
		},
		{
			name:    "empty url",
			mutate:  func(row *ReportExchange) { row.URL = "" },
			wantErr: "validatorcore: empty url",
		},
		{
			name:    "negative seq",
			mutate:  func(row *ReportExchange) { row.Seq = -1 },
			wantErr: "validatorcore: negative seq",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openMigratedProductionCore(t)
			row := newMinimalExchange("run-invalid")
			tt.mutate(row)

			err := core.InsertReportExchange(t.Context(), row)
			if err == nil {
				t.Fatal("expected validation error")
			}

			if err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}

			var storeErr *StoreError
			if errors.As(err, &storeErr) {
				t.Fatal("invalid input must be rejected before store insert")
			}

			if countReportExchanges(t, core, allTestRunIDs) != 0 {
				t.Fatal("invalid input must not write rows")
			}
		})
	}
}

func TestLookupReportExchangeID_ReturnsExistingID(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-lookup-existing"
	createTestRun(t, core.DB(), runID)

	reqID := "req-lookup"
	row := newMinimalExchange(runID)
	row.RequestID = &reqID

	if err := core.InsertReportExchange(ctx, row); err != nil {
		t.Fatalf("InsertReportExchange: %v", err)
	}

	got, err := core.LookupReportExchangeID(ctx, runID, row.Direction, reqID)
	if err != nil {
		t.Fatalf("LookupReportExchangeID: %v", err)
	}

	if got == 0 || got != row.ExchangeID {
		t.Fatalf("lookup id = %d, want %d", got, row.ExchangeID)
	}
}

func TestLookupReportExchangeID_RejectsIncompleteKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		core      func(*testing.T) *Core
		testRunID string
		direction string
		requestID string
		wantErr   string
	}{
		{
			name:      "empty test_run_id",
			core:      openMigratedProductionCore,
			direction: "out",
			requestID: "req",
			wantErr:   "validatorcore: empty test_run_id",
		},
		{
			name:      "empty direction",
			core:      openMigratedProductionCore,
			testRunID: "run",
			requestID: "req",
			wantErr:   "validatorcore: empty direction",
		},
		{
			name:      "empty request_id",
			core:      openMigratedProductionCore,
			testRunID: "run",
			direction: "out",
			wantErr:   "validatorcore: empty request_id",
		},
		{
			name:      "nil store",
			core:      func(*testing.T) *Core { return nil },
			testRunID: "run",
			direction: "out",
			requestID: "req",
			wantErr:   "validatorcore: store is not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.core(t).LookupReportExchangeID(t.Context(), tt.testRunID, tt.direction, tt.requestID)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestIsDuplicateReportExchange(t *testing.T) {
	t.Parallel()

	if IsDuplicateReportExchange(nil) {
		t.Fatal("nil error is not a duplicate")
	}

	if !IsDuplicateReportExchange(gorm.ErrDuplicatedKey) {
		t.Fatal("gorm duplicate must match")
	}

	if !IsDuplicateReportExchange(NewStoreError(OpInsertReportExchange, gorm.ErrDuplicatedKey)) {
		t.Fatal("wrapped insert duplicate must match")
	}
}
