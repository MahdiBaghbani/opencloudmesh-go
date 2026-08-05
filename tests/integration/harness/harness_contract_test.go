// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestSubprocessConfig_needsSecureTransport(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want bool
	}{
		{name: "strict mode requires https", mode: "strict", want: true},
		{name: "empty mode requires https", mode: "", want: true},
		{name: "dev mode allows http", mode: "dev", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := needsSecureTransport(tc.mode)
			if got != tc.want {
				t.Fatalf("needsSecureTransport(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

func TestSubprocessConfig_extraTLSMode(t *testing.T) {
	mode, hasTable := extraTLSMode(`[tls]
mode = "off"
`)
	if !hasTable {
		t.Fatal("expected [tls] table")
	}

	if mode != "off" {
		t.Fatalf("extraTLSMode mode = %q, want off", mode)
	}

	mode, hasTable = extraTLSMode("# no tls table\nlisten_addr = \":8080\"\n")
	if hasTable {
		t.Fatal("did not expect [tls] table")
	}

	if mode != "" {
		t.Fatalf("extraTLSMode mode = %q, want empty", mode)
	}
}

func TestSubprocessConfig_extraDefinesPublicOrigin(t *testing.T) {
	if !extraDefinesPublicOrigin(`public_origin = "http://example.test"`) {
		t.Fatal("expected root public_origin to be detected")
	}

	if extraDefinesPublicOrigin(`[server]
public_origin = "http://ignored.test"
`) {
		t.Fatal("table-scoped public_origin must not count")
	}
}

func TestSubprocessConfig_generateTOMLConfigTransport(t *testing.T) {
	t.Run("dev mode uses tls off", func(t *testing.T) {
		cfg := generateTOMLConfig("test", 8080, "/tmp", "dev", false, "", "", "", "")
		if !strings.Contains(cfg, `mode = "off"`) {
			t.Fatalf("expected tls off in generated config:\n%s", cfg)
		}

		if strings.Contains(cfg, `mode = "selfsigned"`) {
			t.Fatal("did not expect selfsigned TLS for dev mode")
		}
	})

	t.Run("strict mode uses selfsigned tls", func(t *testing.T) {
		cfg := generateTOMLConfig("test", 8443, "/tmp", "strict", false, "", "", "", "")
		if !strings.Contains(cfg, `mode = "selfsigned"`) {
			t.Fatalf("expected selfsigned TLS in generated config:\n%s", cfg)
		}
	})

	t.Run("extra tls table overrides preset block", func(t *testing.T) {
		extra := `[tls]
mode = "off"
`

		cfg := generateTOMLConfig("test", 8080, "/tmp", "strict", false, "", "", "", extra)
		if strings.Count(cfg, "[tls]") != 1 {
			t.Fatalf("expected single [tls] table, got:\n%s", cfg)
		}
	})
}

func TestSubprocessConfig_generateTOMLConfigPersistence(t *testing.T) {
	t.Run("default pins memory backend", func(t *testing.T) {
		// Clear ambient env so Load sees only the generated TOML.
		t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

		// Strict preset defaults to sqlite; harness pins memory for
		// test isolation (deterministic, fast, no on-disk state).
		// Pure-Go sqlite works with CGO_ENABLED=0.
		raw := generateTOMLConfig("test", 8080, "/tmp", "strict", false, "", "", "", "")
		wantPin := fmt.Sprintf("[persistence]\nbackend = %q\n", config.BackendMemory)

		if !strings.Contains(raw, wantPin) {
			t.Fatalf("expected memory persistence pin in generated config:\n%s", raw)
		}

		// Empty DataDir pin: harness emits backend only (no data_dir key).
		if strings.Contains(raw, "data_dir") {
			t.Fatalf("expected empty DataDir pin (no data_dir key), got:\n%s", raw)
		}

		loaded := loadGeneratedConfig(t, raw)
		if loaded.Persistence.Backend != config.BackendMemory {
			t.Fatalf("Persistence.Backend = %q, want %q", loaded.Persistence.Backend, config.BackendMemory)
		}

		// Backend pin leaves data_dir unset, so Strict's DataDir is retained.
		if loaded.Persistence.DataDir != config.DefaultPersistenceDataDir {
			t.Fatalf("Persistence.DataDir = %q, want %q", loaded.Persistence.DataDir, config.DefaultPersistenceDataDir)
		}
	})

	t.Run("persistence table override is honored", func(t *testing.T) {
		t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

		extra := fmt.Sprintf(`[persistence]
backend = %q
data_dir = %q
`, config.BackendSQLite, config.DefaultPersistenceDataDir)

		raw := generateTOMLConfig("test", 8080, "/tmp", "strict", false, "", "", "", extra)
		if strings.Count(raw, "[persistence]") != 1 {
			t.Fatalf("expected single [persistence] table, got:\n%s", raw)
		}

		if !strings.Contains(raw, fmt.Sprintf("backend = %q", config.BackendSQLite)) {
			t.Fatalf("expected override backend in generated config:\n%s", raw)
		}

		if !strings.Contains(raw, fmt.Sprintf("data_dir = %q", config.DefaultPersistenceDataDir)) {
			t.Fatalf("expected override data_dir in generated config:\n%s", raw)
		}

		loaded := loadGeneratedConfig(t, raw)
		if loaded.Persistence.Backend != config.BackendSQLite {
			t.Fatalf("Persistence.Backend = %q, want %q", loaded.Persistence.Backend, config.BackendSQLite)
		}

		if loaded.Persistence.DataDir != config.DefaultPersistenceDataDir {
			t.Fatalf("Persistence.DataDir = %q, want %q", loaded.Persistence.DataDir, config.DefaultPersistenceDataDir)
		}
	})
}

func loadGeneratedConfig(t *testing.T, raw string) *config.Config {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatalf("write generated config: %v", err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load generated config: %v", err)
	}

	return cfg
}
