// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"sync"
	"testing"

	"gorm.io/gorm"
)

func TestFinders_SharedCoreConcurrent(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-shared-core"

	seedActiveRun(t, core, runID, "peer.example", true)
	setBobUserID(t, core, runID, "bob-shared")
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleIncomingFromTarget,
		SenderHost:    "peer.example",
		ProviderID:    "share-in",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     1,
	})
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "peer.example",
		ProviderID:    "share-shared",
		LocalIdentity: LocalIdentityB,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     2,
	})

	const (
		workers = 8
		iters   = 32
	)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		faults = []concurrentFinderFault{}
	)

	start := make(chan struct{})

	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()

			<-start

			for range iters {
				if fault := probeSharedCoreFinders(core, ctx, runID); fault != nil {
					recordFinderFault(&mu, &faults, *fault)

					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	for _, fault := range faults {
		t.Errorf(
			"%s: got %q err %v, want %q",
			fault.method,
			fault.got,
			fault.err,
			fault.want,
		)
	}
}

func TestFindCorrelationAnyStatus_ABRunIsolation(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runA := "run-isolate-a"
	runB := "run-isolate-b"

	seedActiveRun(t, core, runA, "peer-a.example", true)
	seedActiveRun(t, core, runB, "peer-b.example", true)

	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runA,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "peer.example",
		ProviderID:    "share-isolate",
		LocalIdentity: LocalIdentityA,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     1,
	})
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runB,
		Role:          RoleOutgoingToTarget,
		SenderHost:    "peer.example",
		ProviderID:    "share-isolate",
		LocalIdentity: LocalIdentityB,
		Status:        CorrelationStatusPending,
		CreatedAt:     2,
	})

	gotA, err := core.FindCorrelationAnyStatus(
		ctx,
		RoleOutgoingToTarget,
		"peer.example",
		"share-isolate",
		LocalIdentityA,
	)
	if err != nil {
		t.Fatalf("FindCorrelationAnyStatus a: %v", err)
	}

	gotB, err := core.FindCorrelationAnyStatus(
		ctx,
		RoleOutgoingToTarget,
		"peer.example",
		"share-isolate",
		LocalIdentityB,
	)
	if err != nil {
		t.Fatalf("FindCorrelationAnyStatus b: %v", err)
	}

	if gotA != runA {
		t.Fatalf("FindCorrelationAnyStatus a = %q, want %q", gotA, runA)
	}

	if gotB != runB {
		t.Fatalf("FindCorrelationAnyStatus b = %q, want %q", gotB, runB)
	}

	if gotA == gotB {
		t.Fatalf("A and B isolation crossed: both returned %q", gotA)
	}
}

func TestFinders_InactiveRunCorrelationNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		runID  string
		status string
	}{
		{
			name:   "confirmed",
			runID:  "run-inactive-confirmed",
			status: CorrelationStatusConfirmed,
		},
		{
			name:   "pending",
			runID:  "run-inactive-pending",
			status: CorrelationStatusPending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()

			seedActiveRun(t, core, tt.runID, "peer.example", false)
			seedCorrelation(t, core, ShareCorrelation{
				TestRunID:     tt.runID,
				Role:          RoleOutgoingToTarget,
				SenderHost:    "peer.example",
				ProviderID:    "share-inactive",
				LocalIdentity: LocalIdentityA,
				Status:        tt.status,
				CreatedAt:     1,
			})

			if _, err := core.FindActiveCorrelation(
				ctx,
				RoleOutgoingToTarget,
				"peer.example",
				"share-inactive",
				LocalIdentityA,
			); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf(
					"FindActiveCorrelation inactive %s: %v, want ErrRecordNotFound",
					tt.name,
					err,
				)
			}

			if _, err := core.FindCorrelationAnyStatus(
				ctx,
				RoleOutgoingToTarget,
				"peer.example",
				"share-inactive",
				LocalIdentityA,
			); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Fatalf(
					"FindCorrelationAnyStatus inactive %s: %v, want ErrRecordNotFound",
					tt.name,
					err,
				)
			}
		})
	}
}

func TestFindActiveByTarget_IgnoresBobUserID(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-empty-bob"
	host := "peer.example"

	seedActiveRun(t, core, runID, host, true)
	seedCorrelation(t, core, ShareCorrelation{
		TestRunID:     runID,
		Role:          RoleOutgoingToTarget,
		SenderHost:    host,
		ProviderID:    "share-empty-bob",
		LocalIdentity: LocalIdentityB,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     1,
	})

	gotNull, err := core.FindActiveByTarget(ctx, host)
	if err != nil {
		t.Fatalf("FindActiveByTarget with null bob_user_id: %v", err)
	}

	if gotNull != runID {
		t.Fatalf("FindActiveByTarget with null bob_user_id = %q, want %q", gotNull, runID)
	}

	mustExec(t, core.DB(),
		"UPDATE test_run SET bob_user_id = '' WHERE test_run_id = '"+runID+"'")

	gotEmpty, err := core.FindActiveByTarget(ctx, host)
	if err != nil {
		t.Fatalf("FindActiveByTarget with empty bob_user_id: %v", err)
	}

	if gotEmpty != runID {
		t.Fatalf("FindActiveByTarget with empty bob_user_id = %q, want %q", gotEmpty, runID)
	}
}

func TestFindActiveByTarget_AmbiguousSameTarget(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	mustExec(t, core.DB(), "DROP INDEX idx_test_run_active_per_target")
	seedActiveRun(t, core, "run-b-active-1", "peer.example", true)
	seedActiveRun(t, core, "run-b-active-2", "peer.example", true)
	setBobUserID(t, core, "run-b-active-1", "bob-user-1")
	setBobUserID(t, core, "run-b-active-2", "bob-user-2")

	got, err := core.FindActiveByTarget(ctx, "peer.example")
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FindActiveByTarget ambiguous: got %q err %v, want ErrRecordNotFound", got, err)
	}

	rows, listErr := core.ListActive(ctx)
	if listErr != nil {
		t.Fatalf("ListActive: %v", listErr)
	}

	if len(rows) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(rows))
	}
}

type concurrentFinderFault struct {
	method string
	got    string
	want   string
	err    error
}

type sharedCoreFinderCall struct {
	method string
	invoke func() (string, error)
}

func probeSharedCoreFinders(
	core *Core,
	ctx context.Context,
	runID string,
) *concurrentFinderFault {
	calls := []sharedCoreFinderCall{
		{
			method: "FindActiveByTarget",
			invoke: func() (string, error) {
				return core.FindActiveByTarget(ctx, "peer.example")
			},
		},
		{
			method: "ListActive",
			invoke: func() (string, error) {
				rows, err := core.ListActive(ctx)
				if err != nil {
					return "", err
				}

				if len(rows) != 1 || rows[0] == nil {
					return "", gorm.ErrRecordNotFound
				}

				return rows[0].TestRunID, nil
			},
		},
		{
			method: "FindActiveCorrelation a",
			invoke: func() (string, error) {
				return core.FindActiveCorrelation(
					ctx,
					RoleIncomingFromTarget,
					"peer.example",
					"share-in",
					LocalIdentityA,
				)
			},
		},
		{
			method: "FindCorrelationAnyStatus a",
			invoke: func() (string, error) {
				return core.FindCorrelationAnyStatus(
					ctx,
					RoleIncomingFromTarget,
					"peer.example",
					"share-in",
					LocalIdentityA,
				)
			},
		},
		{
			method: "FindActiveCorrelation b",
			invoke: func() (string, error) {
				return core.FindActiveCorrelation(
					ctx,
					RoleOutgoingToTarget,
					"peer.example",
					"share-shared",
					LocalIdentityB,
				)
			},
		},
		{
			method: "FindCorrelationAnyStatus b",
			invoke: func() (string, error) {
				return core.FindCorrelationAnyStatus(
					ctx,
					RoleOutgoingToTarget,
					"peer.example",
					"share-shared",
					LocalIdentityB,
				)
			},
		},
	}

	for _, call := range calls {
		got, err := call.invoke()
		if err != nil || got != runID {
			return &concurrentFinderFault{
				method: call.method,
				got:    got,
				want:   runID,
				err:    err,
			}
		}
	}

	return nil
}

func recordFinderFault(
	mu *sync.Mutex,
	faults *[]concurrentFinderFault,
	fault concurrentFinderFault,
) {
	mu.Lock()

	*faults = append(*faults, fault)
	mu.Unlock()
}

func setBobUserID(t *testing.T, core *Core, runID, bobUserID string) {
	t.Helper()

	if err := core.DB().WithContext(t.Context()).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bobUserID).Error; err != nil {
		t.Fatalf("set bob_user_id: %v", err)
	}
}
