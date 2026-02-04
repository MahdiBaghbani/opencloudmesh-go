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
		return nil, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tls_root_ca_file: read failed: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("tls_root_ca_file: no valid PEM certificates found")
		}
	}

	if caDir != "" {
		entries, err := os.ReadDir(caDir)
		if err != nil {
			return nil, fmt.Errorf("tls_root_ca_dir: read failed: %w", err)
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
				return nil, fmt.Errorf("tls_root_ca_dir: stat %q failed: %w", path, err)
			}
			if !fi.Mode().IsRegular() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("tls_root_ca_dir: read %q failed: %w", path, err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("tls_root_ca_dir: %q: no valid PEM certificates found", path)
			}
		}
	}

	return pool, nil
}
