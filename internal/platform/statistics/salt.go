// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package statistics provides shared redaction and statistics hashing helpers.
package statistics

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// RedactionSaltFileName is the basename of the shared 32-byte salt file under
	// the persistence data directory. The same salt backs evidence redaction and
	// statistics host hashing (LB-29).
	RedactionSaltFileName = "redaction.salt"

	// redactionSaltClaimFileName is an O_EXCL coordination marker while a fresh
	// salt is being installed. It is removed after a successful install.
	redactionSaltClaimFileName = "redaction.salt.claim"

	// RedactionSaltSize is the required salt length in bytes.
	RedactionSaltSize = 32

	redactionSaltFileMode = 0o600

	redactionSaltInstallMaxAttempts = 100

	redactionSaltInstallRetryInterval = 5 * time.Millisecond
)

var errRedactionSaltMissing = errors.New("statistics: redaction salt not installed")

var (
	redactionSaltHookMu sync.RWMutex

	// redactionSaltInstallDelay is set by tests to widen the install race window.
	redactionSaltInstallDelay func()

	// redactionSaltPostClaimDelay is set by tests to interleave work after the
	// exclusive claim is acquired and before minting begins.
	redactionSaltPostClaimDelay func()
)

func setRedactionSaltInstallDelayHook(h func()) {
	redactionSaltHookMu.Lock()
	redactionSaltInstallDelay = h
	redactionSaltHookMu.Unlock()
}

func clearRedactionSaltInstallDelayHook() {
	setRedactionSaltInstallDelayHook(nil)
}

func setRedactionSaltPostClaimDelayHook(h func()) {
	redactionSaltHookMu.Lock()
	redactionSaltPostClaimDelay = h
	redactionSaltHookMu.Unlock()
}

func clearRedactionSaltPostClaimDelayHook() {
	setRedactionSaltPostClaimDelayHook(nil)
}

func invokeRedactionSaltPostClaimDelay() {
	redactionSaltHookMu.RLock()

	hook := redactionSaltPostClaimDelay

	redactionSaltHookMu.RUnlock()

	if hook != nil {
		hook()
	}
}

func invokeRedactionSaltInstallDelay() {
	redactionSaltHookMu.RLock()

	hook := redactionSaltInstallDelay

	redactionSaltHookMu.RUnlock()

	if hook != nil {
		hook()
	}
}

// LoadRedactionSalt reads or mints the shared redaction salt at
// filepath.Join(dataDir, RedactionSaltFileName). The file must be mode 0600.
// Startup fails when the directory is unusable, the file is unreadable, an
// existing file is not exactly RedactionSaltSize bytes, or permissions are not
// exactly 0600.
func LoadRedactionSalt(dataDir string) ([]byte, error) {
	if dataDir == "" {
		return nil, errors.New("statistics: persistence.data_dir is required for redaction salt")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("statistics: create data dir: %w", err)
	}

	path := filepath.Join(dataDir, RedactionSaltFileName)

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-configured data_dir at startup
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("statistics: read redaction salt: %w", err)
		}

		return mintOrLoadRedactionSalt(dataDir, path)
	}

	return validateAndCopySalt(path, data)
}

func mintOrLoadRedactionSalt(dataDir, path string) ([]byte, error) {
	claimPath := filepath.Join(dataDir, redactionSaltClaimFileName)

	for range redactionSaltInstallMaxAttempts {
		salt, readErr := tryReadExistingRedactionSalt(path)
		if readErr == nil {
			return salt, nil
		}

		if !errors.Is(readErr, errRedactionSaltMissing) {
			return nil, readErr
		}

		acquired, acquireErr := tryAcquireRedactionSaltClaim(claimPath)
		if acquireErr != nil {
			return nil, acquireErr
		}

		if acquired {
			invokeRedactionSaltPostClaimDelay()

			salt, readErr := tryReadExistingRedactionSalt(path)
			if readErr == nil {
				removeIgnoringNotExist(claimPath)

				return salt, nil
			}

			if !errors.Is(readErr, errRedactionSaltMissing) {
				removeIgnoringNotExist(claimPath)

				return nil, readErr
			}

			salt, installErr := installRedactionSalt(path)

			removeIgnoringNotExist(claimPath)

			return salt, installErr
		}

		time.Sleep(redactionSaltInstallRetryInterval)
	}

	salt, readErr := tryReadExistingRedactionSalt(path)
	if readErr == nil {
		return salt, nil
	}

	if errors.Is(readErr, errRedactionSaltMissing) {
		return nil, fmt.Errorf(
			"statistics: timed out waiting for redaction salt install; claim remains at %q for cleanup",
			claimPath,
		)
	}

	return nil, readErr
}

func tryReadExistingRedactionSalt(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-configured data_dir at startup
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errRedactionSaltMissing
		}

		return nil, fmt.Errorf("statistics: read redaction salt: %w", err)
	}

	return validateAndCopySalt(path, data)
}

func tryAcquireRedactionSaltClaim(claimPath string) (bool, error) {
	f, err := os.OpenFile(claimPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, redactionSaltFileMode) //nolint:gosec // G304: path is operator-configured data_dir at startup
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}

		return false, fmt.Errorf("statistics: create redaction salt claim: %w", err)
	}

	if err := f.Close(); err != nil {
		removeIgnoringNotExist(claimPath)

		return false, fmt.Errorf("statistics: close redaction salt claim: %w", err)
	}

	return true, nil
}

func installRedactionSalt(path string) ([]byte, error) {
	salt := make([]byte, RedactionSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("statistics: generate redaction salt: %w", err)
	}

	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, RedactionSaltFileName+".tmp.*")
	if err != nil {
		return nil, fmt.Errorf("statistics: create redaction salt temp file: %w", err)
	}

	tmpPath := tmp.Name()
	cleanupTemp := true

	defer func() {
		if cleanupTemp {
			removeIgnoringNotExist(tmpPath)
		}
	}()

	if err := tmp.Chmod(redactionSaltFileMode); err != nil {
		return nil, fmt.Errorf("statistics: chmod redaction salt temp file: %w", err)
	}

	if _, err := tmp.Write(salt); err != nil {
		return nil, fmt.Errorf("statistics: write redaction salt: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("statistics: sync redaction salt: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("statistics: close redaction salt temp file: %w", err)
	}

	invokeRedactionSaltInstallDelay()

	existing, readErr := tryReadExistingRedactionSalt(path)
	if readErr == nil {
		return existing, nil
	}

	if !errors.Is(readErr, errRedactionSaltMissing) {
		return nil, readErr
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return nil, fmt.Errorf("statistics: install redaction salt: %w", err)
	}

	if err := syncParentDirectory(path); err != nil {
		return nil, err
	}

	cleanupTemp = false

	out := make([]byte, RedactionSaltSize)
	copy(out, salt)

	return out, nil
}

func syncParentDirectory(path string) (err error) {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("statistics: open parent directory: %w", err)
	}

	defer func() {
		if closeErr := dir.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("statistics: close parent directory: %w", closeErr)
		}
	}()

	if err = dir.Sync(); err != nil {
		return fmt.Errorf("statistics: sync parent directory: %w", err)
	}

	return nil
}

func validateAndCopySalt(path string, data []byte) ([]byte, error) {
	if len(data) != RedactionSaltSize {
		return nil, fmt.Errorf(
			"statistics: redaction salt at %q must be %d bytes, got %d",
			path,
			RedactionSaltSize,
			len(data),
		)
	}

	if err := ensureRedactionSaltMode(path); err != nil {
		return nil, err
	}

	out := make([]byte, RedactionSaltSize)
	copy(out, data)

	return out, nil
}

func ensureRedactionSaltMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("statistics: stat redaction salt: %w", err)
	}

	mode := info.Mode().Perm()
	if mode == redactionSaltFileMode {
		return nil
	}

	return fmt.Errorf("statistics: redaction salt at %q must be mode 0600, got %o", path, mode)
}

func removeIgnoringNotExist(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Non-NotExist removal failures are tolerated during best-effort cleanup.
		_ = err
	}
}
