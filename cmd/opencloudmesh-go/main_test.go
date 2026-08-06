// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func TestPrintVersionTrue(t *testing.T) {
	var buf bytes.Buffer

	done, err := printVersion(true, &buf)
	if err != nil {
		t.Fatalf("printVersion(true) err = %v, want nil", err)
	}

	if !done {
		t.Fatal("printVersion(true) done = false, want true")
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("printVersion(true) wrote %q, want %q", buf.String(), want)
	}
}

func TestPrintVersionFalse(t *testing.T) {
	var buf bytes.Buffer

	done, err := printVersion(false, &buf)
	if err != nil {
		t.Fatalf("printVersion(false) err = %v, want nil", err)
	}

	if done {
		t.Fatal("printVersion(false) done = true, want false")
	}

	if buf.Len() != 0 {
		t.Fatalf("printVersion(false) wrote %q, want nothing", buf.String())
	}
}

func TestRunVersionShortFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"-version"}, &buf)
	if code != 0 {
		t.Fatalf("run(-version) = %d, want 0", code)
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("run(-version) wrote %q, want %q", buf.String(), want)
	}
}

func TestRunVersionLongFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--version"}, &buf)
	if code != 0 {
		t.Fatalf("run(--version) = %d, want 0", code)
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("run(--version) wrote %q, want %q", buf.String(), want)
	}
}

func TestRunBadFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--nonexistent-flag"}, &buf)
	if code != 2 {
		t.Fatalf("run(--nonexistent-flag) = %d, want 2", code)
	}
}

func TestRunHelpShortFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"-h"}, &buf)
	if code != 0 {
		t.Fatalf("run(-h) = %d, want 0", code)
	}
}

func TestRunHelpLongFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--help"}, &buf)
	if code != 0 {
		t.Fatalf("run(--help) = %d, want 0", code)
	}
}

func TestWriteBootstrapPasswordFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-admin-password")
	password := "generated-secret-value"

	var logBuf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := writeBootstrapPasswordFile(path, password, logger); err != nil {
		t.Fatalf("writeBootstrapPasswordFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat password file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("password file mode = %o, want 0600", info.Mode().Perm())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}

	if string(content) != password {
		t.Errorf("password file contents = %q, want %q", string(content), password)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, path) {
		t.Errorf("log output missing password file path %q: %s", path, logOutput)
	}

	if strings.Contains(logOutput, password) {
		t.Error("generated password must not appear in log output")
	}

	if !strings.Contains(logOutput, "rotate via admin UI/CLI") {
		t.Errorf("log output missing rotation hint: %s", logOutput)
	}
}

func TestIsUnsupportedDirSyncError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enotsup", err: syscall.ENOTSUP, want: true},
		{name: "einval", err: syscall.EINVAL, want: true},
		{name: "erofs", err: syscall.EROFS, want: true},
		{name: "wrapped enotsup", err: fmt.Errorf("sync: %w", syscall.ENOTSUP), want: true},
		{name: "other", err: errors.New("io error"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isUnsupportedDirSyncError(tc.err); got != tc.want {
				t.Errorf("isUnsupportedDirSyncError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWriteBootstrapPasswordFile_OverwritesPermissiveMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-admin-password")
	password := "generated-secret-value"

	if err := os.WriteFile(path, []byte("old-password"), 0644); err != nil {
		t.Fatalf("precreate password file: %v", err)
	}

	preInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat precreated password file: %v", err)
	}

	if preInfo.Mode().Perm() != 0644 {
		t.Fatalf("precreated password file mode = %o, want 0644", preInfo.Mode().Perm())
	}

	var logBuf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err = writeBootstrapPasswordFile(path, password, logger); err != nil {
		t.Fatalf("writeBootstrapPasswordFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat password file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("password file mode = %o, want 0600", info.Mode().Perm())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}

	if string(content) != password {
		t.Errorf("password file contents = %q, want %q", string(content), password)
	}
}

func TestBootstrapAdmin_WritesGeneratedPasswordFile(t *testing.T) {
	dir := t.TempDir()

	prevDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	if chdirErr := os.Chdir(dir); chdirErr != nil {
		t.Fatalf("chdir: %v", chdirErr)
	}

	t.Cleanup(func() {
		if chdirErr := os.Chdir(prevDir); chdirErr != nil {
			t.Errorf("restore working directory: %v", chdirErr)
		}
	})

	var logBuf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	repo := identity.NewMemoryPartyRepo()
	auth := identity.NewUserAuthFast()

	cfg := &config.Config{
		Server: config.ServerConfig{
			BootstrapAdmin: config.BootstrapAdminConfig{
				Username: "admin",
			},
		},
	}

	deps := &wiring.Deps{
		PartyRepo: repo,
		UserAuth:  auth,
	}

	if bootstrapErr := bootstrapAdmin(context.Background(), cfg, deps, logger); bootstrapErr != nil {
		t.Fatalf("bootstrapAdmin failed: %v", bootstrapErr)
	}

	bootstrapFilePath := filepath.Join(dir, defaultBootstrapFilePath)

	content, err := os.ReadFile(bootstrapFilePath)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}

	password := string(content)
	if password == "" {
		t.Fatal("expected non-empty generated password in file")
	}

	info, err := os.Stat(bootstrapFilePath)
	if err != nil {
		t.Fatalf("stat password file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("password file mode = %o, want 0600", info.Mode().Perm())
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, bootstrapFilePath) {
		t.Errorf("log output missing password file path %q: %s", bootstrapFilePath, logOutput)
	}

	if strings.Contains(logOutput, password) {
		t.Error("generated password must not appear in log output")
	}

	user, err := repo.GetByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("admin not found: %v", err)
	}

	if err := auth.VerifyPassword(user.PasswordHash, password); err != nil {
		t.Errorf("file password should match stored hash: %v", err)
	}
}

func TestResolveBootstrapPasswordFilePath(t *testing.T) {
	cwd := t.TempDir()

	tests := []struct {
		name     string
		cfg      *config.Config
		wantPath string
	}{
		{
			name: "explicit relative password file",
			cfg: &config.Config{
				Server: config.ServerConfig{
					BootstrapAdmin: config.BootstrapAdminConfig{
						PasswordFile: "secrets/admin.pass",
					},
				},
			},
			wantPath: filepath.Join(cwd, "secrets/admin.pass"),
		},
		{
			name: "explicit absolute password file",
			cfg: &config.Config{
				Server: config.ServerConfig{
					BootstrapAdmin: config.BootstrapAdminConfig{
						PasswordFile: "/var/lib/ocm/admin.pass",
					},
				},
			},
			wantPath: "/var/lib/ocm/admin.pass",
		},
		{
			name: "explicit password file overrides data dir",
			cfg: &config.Config{
				Server: config.ServerConfig{
					BootstrapAdmin: config.BootstrapAdminConfig{
						PasswordFile: "secrets/admin.pass",
					},
				},
				Persistence: config.PersistenceConfig{
					DataDir: ".ocm/data",
				},
			},
			wantPath: filepath.Join(cwd, "secrets/admin.pass"),
		},
		{
			name: "data dir default",
			cfg: &config.Config{
				Persistence: config.PersistenceConfig{
					DataDir: ".ocm/data",
				},
			},
			wantPath: filepath.Join(cwd, ".ocm/data/bootstrap-admin-password"),
		},
		{
			name:     "cwd default",
			cfg:      &config.Config{},
			wantPath: filepath.Join(cwd, defaultBootstrapFilePath),
		},
	}

	prevDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	if chdirErr := os.Chdir(cwd); chdirErr != nil {
		t.Fatalf("chdir: %v", chdirErr)
	}

	t.Cleanup(func() {
		if chdirErr := os.Chdir(prevDir); chdirErr != nil {
			t.Errorf("restore working directory: %v", chdirErr)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBootstrapPasswordFilePath(tc.cfg)
			if err != nil {
				t.Fatalf("resolveBootstrapPasswordFilePath failed: %v", err)
			}

			if got != tc.wantPath {
				t.Errorf("path = %q, want %q", got, tc.wantPath)
			}
		})
	}
}
