// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package tls provides TLS configuration and certificate management.
package tls

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuildRootCAPool builds a merged root CA pool from an optional file and optional directory.
// If both caFile and caDir are empty, returns (nil, nil) so the caller uses system defaults.
// File and dir certs are merged with the system pool when available.
func BuildRootCAPool(caFile, caDir string) (*x509.CertPool, error) {
	if caFile == "" && caDir == "" {
		return nil, nil //nolint:nilnil // intentional: (nil, nil) means no extra CA roots configured; caller falls back to system defaults
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if caFile != "" {
		if err := appendCertsFromFile(pool, caFile, "tls_root_ca_file"); err != nil {
			return nil, err
		}
	}

	if caDir != "" {
		if err := appendCertsFromDir(pool, caDir); err != nil {
			return nil, err
		}
	}

	return pool, nil
}

func appendCertsFromFile(pool *x509.CertPool, path, label string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: read failed: %w", label, err)
	}

	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("%s: no valid PEM certificates found", label)
	}

	return nil
}

func appendCertsFromDir(pool *x509.CertPool, caDir string) error {
	entries, err := os.ReadDir(caDir)
	if err != nil {
		return fmt.Errorf("tls_root_ca_dir: read failed: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}

		base := strings.ToLower(e.Name())
		if !strings.HasSuffix(base, ".pem") && !strings.HasSuffix(base, ".crt") {
			continue
		}

		path := filepath.Join(caDir, e.Name())

		fi, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("tls_root_ca_dir: stat %q failed: %w", path, err)
		}

		if !fi.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("tls_root_ca_dir: read %q failed: %w", path, err)
		}

		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("tls_root_ca_dir: %q: no valid PEM certificates found", path)
		}
	}

	return nil
}
