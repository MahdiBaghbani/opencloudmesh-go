package harness

import (
	"strings"
	"testing"
)

func TestSubprocessConfig_needsSecureTransport(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		scope string
		want  bool
	}{
		{name: "none scope requires https", mode: "dev", scope: "none", want: true},
		{name: "scoped requires https", mode: "dev", scope: "scoped", want: true},
		// needsSecureTransport is a pure string helper exercised before config
		// validation; an unrecognized scope defaults to a dev-friendly fallback.
		{name: "unknown scope allows http", mode: "dev", scope: "not-a-real-scope", want: false},
		{name: "empty scope with strict mode requires https", mode: "strict", scope: "", want: true},
		{name: "empty scope with dev mode allows http", mode: "dev", scope: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := needsSecureTransport(tc.mode, tc.scope)
			if got != tc.want {
				t.Fatalf("needsSecureTransport(%q, %q) = %v, want %v",
					tc.mode, tc.scope, got, tc.want)
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
	t.Run("unknown scope dev uses tls off", func(t *testing.T) {
		cfg := generateTOMLConfig("test", 8080, "/tmp", "dev", "not-a-real-scope", false, false, "", "", "")
		if !strings.Contains(cfg, `mode = "off"`) {
			t.Fatalf("expected tls off in generated config:\n%s", cfg)
		}
		if strings.Contains(cfg, `mode = "selfsigned"`) {
			t.Fatal("did not expect selfsigned TLS for unknown-scope dev")
		}
	})

	t.Run("none scope uses selfsigned tls", func(t *testing.T) {
		cfg := generateTOMLConfig("test", 8443, "/tmp", "strict", "none", false, false, "", "", "")
		if !strings.Contains(cfg, `mode = "selfsigned"`) {
			t.Fatalf("expected selfsigned TLS in generated config:\n%s", cfg)
		}
	})

	t.Run("extra tls table overrides preset block", func(t *testing.T) {
		extra := `[tls]
mode = "off"
`
		cfg := generateTOMLConfig("test", 8080, "/tmp", "strict", "none", false, false, "", "", extra)
		if strings.Count(cfg, "[tls]") != 1 {
			t.Fatalf("expected single [tls] table, got:\n%s", cfg)
		}
	})
}
