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
