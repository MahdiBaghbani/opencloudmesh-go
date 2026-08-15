// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package statistics

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadRedactionSalt_MintsAndReuses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	first, err := LoadRedactionSalt(dir)
	if err != nil {
		t.Fatalf("first LoadRedactionSalt: %v", err)
	}

	if len(first) != RedactionSaltSize {
		t.Fatalf("salt len = %d, want %d", len(first), RedactionSaltSize)
	}

	info, err := os.Stat(filepath.Join(dir, RedactionSaltFileName))
	if err != nil {
		t.Fatalf("stat salt file: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Errorf("salt mode = %o, want 0600", info.Mode().Perm())
	}

	second, err := LoadRedactionSalt(dir)
	if err != nil {
		t.Fatalf("second LoadRedactionSalt: %v", err)
	}

	if string(first) != string(second) {
		t.Fatal("expected stable salt across loads")
	}
}

func TestLoadRedactionSalt_RejectsEmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, RedactionSaltFileName)

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty salt: %v", err)
	}

	if _, err := LoadRedactionSalt(dir); err == nil {
		t.Fatal("expected error for empty salt file")
	}
}

func TestLoadRedactionSalt_RejectsWrongSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, RedactionSaltFileName)

	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write short salt: %v", err)
	}

	if _, err := LoadRedactionSalt(dir); err == nil {
		t.Fatal("expected error for wrong-size salt file")
	}
}

func TestLoadRedactionSalt_RejectsInsecureMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, RedactionSaltFileName)

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	if err := os.WriteFile(path, salt, 0o644); err != nil {
		t.Fatalf("write insecure salt: %v", err)
	}

	_, err := LoadRedactionSalt(dir)
	if err == nil {
		t.Fatal("expected error for insecure salt permissions")
	}

	if got := err.Error(); !strings.Contains(got, "0600") {
		t.Fatalf("error = %q, want insecure mode failure mentioning 0600", err)
	}
}

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

func TestLoadRedactionSalt_ReusesExistingWithoutClaim(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	first, err := LoadRedactionSalt(dir)
	if err != nil {
		t.Fatalf("seed LoadRedactionSalt: %v", err)
	}

	const workers = 16

	results := make([][]byte, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(idx int) {
			defer wg.Done()

			results[idx], errs[idx] = LoadRedactionSalt(dir)
		}(i)
	}

	wg.Wait()

	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("worker %d error: %v", i, errs[i])
		}

		if string(results[i]) != string(first) {
			t.Fatalf("worker %d salt differs from seeded salt", i)
		}
	}

	claimPath := filepath.Join(dir, redactionSaltClaimFileName)
	if _, err := os.Stat(claimPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claim file should not exist when reusing valid salt, stat err = %v", err)
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

func TestHashStatsHost_RejectsEmptySalt(t *testing.T) {
	t.Parallel()

	if _, err := HashStatsHost(nil, "example.com"); err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestHashStatsHost_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := HashStatsHost([]byte("short"), "example.com"); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}

func TestHashRedactSig_RejectsEmptySalt(t *testing.T) {
	t.Parallel()

	if _, err := HashRedactSig(nil, []byte("token")); err == nil {
		t.Fatal("expected error for empty salt")
	}
}

func TestHashRedactSig_RejectsWrongSizeSalt(t *testing.T) {
	t.Parallel()

	if _, err := HashRedactSig([]byte("short"), []byte("token")); err == nil {
		t.Fatal("expected error for wrong-size salt")
	}
}

func TestHashStatsHostAndRedactSig(t *testing.T) {
	t.Parallel()

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	hostHash, err := HashStatsHost(salt, "Example.COM")
	if err != nil {
		t.Fatalf("HashStatsHost: %v", err)
	}

	hostHash2, err := HashStatsHost(salt, "example.com")
	if err != nil {
		t.Fatalf("HashStatsHost lowercase: %v", err)
	}

	if hostHash != hostHash2 {
		t.Fatalf("host hash mismatch: %q vs %q", hostHash, hostHash2)
	}

	sigHash, err := HashRedactSig(salt, []byte("token-value"))
	if err != nil {
		t.Fatalf("HashRedactSig: %v", err)
	}

	if len(sigHash) != RedactionSaltSize {
		t.Fatalf("sig hash len = %d, want %d", len(sigHash), RedactionSaltSize)
	}
}

func TestHashContextsDoNotCollideForSameInput(t *testing.T) {
	t.Parallel()

	salt := make([]byte, RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 3)
	}

	input := []byte("shared-logical-input")

	hostHash, err := HashStatsHost(salt, string(input))
	if err != nil {
		t.Fatalf("HashStatsHost: %v", err)
	}

	hostHashAgain, err := HashStatsHost(salt, string(input))
	if err != nil {
		t.Fatalf("HashStatsHost repeat: %v", err)
	}

	if hostHash != hostHashAgain {
		t.Fatal("stats-host hash must be stable for the same input")
	}

	sigHash, err := HashRedactSig(salt, input)
	if err != nil {
		t.Fatalf("HashRedactSig: %v", err)
	}

	sigHashAgain, err := HashRedactSig(salt, input)
	if err != nil {
		t.Fatalf("HashRedactSig repeat: %v", err)
	}

	if string(sigHash) != string(sigHashAgain) {
		t.Fatal("redact-sig hash must be stable for the same input")
	}

	sigHashHex := hex.EncodeToString(sigHash)
	if hostHash == sigHashHex {
		t.Fatal("stats-host and redact-sig hashes must not collide for the same input")
	}
}
