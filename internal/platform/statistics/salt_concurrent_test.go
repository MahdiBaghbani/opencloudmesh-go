// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package statistics

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadRedactionSalt_ConcurrentMintReturnsPersistedWinner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	const workers = 32

	results := make([][]byte, workers)
	errs := make([]error, workers)

	start := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(idx int) {
			defer wg.Done()

			<-start

			results[idx], errs[idx] = LoadRedactionSalt(dir)
		}(i)
	}

	close(start)
	wg.Wait()

	assertConcurrentRedactionSaltResults(t, dir, workers, results, errs)
}

//nolint:paralleltest // mutates package-level install delay hooks for race-window testing
func TestLoadRedactionSalt_ConcurrentMintWaitsForInstall(t *testing.T) {
	dir := t.TempDir()

	const workers = 24

	results := make([][]byte, workers)
	errs := make([]error, workers)

	installReady := make(chan struct{})
	releaseInstall := make(chan struct{})

	var installReadyOnce sync.Once

	setRedactionSaltInstallDelayHook(func() {
		installReadyOnce.Do(func() {
			close(installReady)
		})

		<-releaseInstall
	})

	t.Cleanup(clearRedactionSaltInstallDelayHook)

	start := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(idx int) {
			defer wg.Done()

			<-start

			results[idx], errs[idx] = LoadRedactionSalt(dir)
		}(i)
	}

	close(start)

	select {
	case <-installReady:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for install delay hook")
	}

	saltPath := filepath.Join(dir, RedactionSaltFileName)
	if _, err := os.Stat(saltPath); err == nil {
		t.Fatal("final redaction salt must not exist before atomic install completes")
	}

	close(releaseInstall)
	wg.Wait()

	assertConcurrentRedactionSaltResults(t, dir, workers, results, errs)
}

//nolint:paralleltest // mutates package-level delay hooks for TOCTOU coverage
func TestLoadRedactionSalt_ReusesConcurrentWinnerDuringRace(t *testing.T) {
	cases := []struct {
		name       string
		winnerSeed byte
		failMsg    string
		setHook    func(func())
		clearHook  func()
	}{
		{
			name:       "post claim re-read",
			winnerSeed: 99,
			failMsg:    "expected post-claim re-read to return existing winner without minting",
			setHook:    setRedactionSaltPostClaimDelayHook,
			clearHook:  clearRedactionSaltPostClaimDelayHook,
		},
		{
			name:       "install delay before rename",
			winnerSeed: 17,
			failMsg:    "expected pre-rename re-read to return existing winner without overwrite",
			setHook:    setRedactionSaltInstallDelayHook,
			clearHook:  clearRedactionSaltInstallDelayHook,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLoadRedactionSaltReusesConcurrentWinner(
				t,
				tc.setHook,
				tc.clearHook,
				tc.winnerSeed,
				tc.failMsg,
			)
		})
	}
}

func assertLoadRedactionSaltReusesConcurrentWinner(
	t *testing.T,
	setHook func(func()),
	clearHook func(),
	winnerSeed byte,
	failMsg string,
) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, RedactionSaltFileName)

	winner := make([]byte, RedactionSaltSize)
	for i := range winner {
		winner[i] = byte(i) + winnerSeed
	}

	setHook(func() {
		if err := os.WriteFile(path, winner, 0o600); err != nil {
			t.Fatalf("write concurrent winner: %v", err)
		}
	})

	t.Cleanup(clearHook)

	got, err := LoadRedactionSalt(dir)
	if err != nil {
		t.Fatalf("LoadRedactionSalt: %v", err)
	}

	if string(got) != string(winner) {
		t.Fatal(failMsg)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted salt: %v", err)
	}

	if string(persisted) != string(winner) {
		t.Fatal("persisted salt must remain the existing winner")
	}
}

func TestLoadRedactionSalt_TimesOutWaitingOnLiveClaim(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	claimPath := filepath.Join(dir, redactionSaltClaimFileName)

	claim, err := os.OpenFile(claimPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create live claim: %v", err)
	}

	if closeErr := claim.Close(); closeErr != nil {
		t.Fatalf("close live claim: %v", closeErr)
	}

	_, err = LoadRedactionSalt(dir)
	if err == nil {
		t.Fatal("expected timeout while another installer holds the claim")
	}

	if got := err.Error(); !strings.Contains(got, "timed out waiting for redaction salt install") {
		t.Fatalf("error = %q, want install wait timeout", err)
	}

	if got := err.Error(); !strings.Contains(got, claimPath) {
		t.Fatalf("error = %q, want claim path for cleanup", err)
	}

	if _, err := os.Stat(claimPath); err != nil {
		t.Fatalf("live claim should remain for cleanup: %v", err)
	}

	saltPath := filepath.Join(dir, RedactionSaltFileName)
	if _, err := os.Stat(saltPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final salt must not exist while install is blocked, stat err = %v", err)
	}
}

func assertConcurrentRedactionSaltResults(
	t *testing.T,
	dir string,
	workers int,
	results [][]byte,
	errs []error,
) {
	t.Helper()

	path := filepath.Join(dir, RedactionSaltFileName)

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted salt: %v", err)
	}

	if len(persisted) != RedactionSaltSize {
		t.Fatalf("persisted salt len = %d, want %d", len(persisted), RedactionSaltSize)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat persisted salt: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted salt mode = %o, want 0600", info.Mode().Perm())
	}

	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d error: %v", i, errs[i])
		}

		if len(results[i]) != RedactionSaltSize {
			t.Fatalf("worker %d salt len = %d, want %d", i, len(results[i]), RedactionSaltSize)
		}

		if string(results[i]) != string(persisted) {
			t.Fatalf("worker %d salt differs from persisted file", i)
		}
	}

	for i := 1; i < workers; i++ {
		if string(results[i]) != string(results[0]) {
			t.Fatalf("worker salts differ: 0 vs %d", i)
		}
	}

	claimPath := filepath.Join(dir, redactionSaltClaimFileName)
	if _, err := os.Stat(claimPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claim file should be removed after install, stat err = %v", err)
	}
}
