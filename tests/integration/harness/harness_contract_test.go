package harness

import (
	"strings"
	"testing"
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
