package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
)

func TestLoad_InvalidNestedSSRFMode_FailsFast(t *testing.T) {
	// Clear ambient env override so the SSRF validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "block"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid outbound_http.ssrf.mode")
	}
	if !strings.Contains(err.Error(), "invalid outbound_http.ssrf.mode") {
		t.Errorf("expected ssrf.mode error, got: %v", err)
	}
}

func TestLoad_SSRF_NestedSchemaLoads(t *testing.T) {
	// Clear ambient env override so the SSRF load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"

[outbound_http.ssrf]
mode = "strict"

[outbound_http.ssrf.route_policies.internal]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080, 8443]
allow_ip_literals = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v (nested SSRF schema should load)", err)
	}

	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected ssrf.mode strict, got %q", cfg.OutboundHTTP.SSRF.Mode)
	}
	policy, ok := cfg.OutboundHTTP.SSRF.RoutePolicies["internal"]
	if !ok {
		t.Fatal("expected route policy 'internal' to be defined")
	}
	if len(policy.AllowPrivateHostSuffixes) != 1 || policy.AllowPrivateHostSuffixes[0] != "svc.cluster.local" {
		t.Errorf("unexpected allow_private_host_suffixes: %v", policy.AllowPrivateHostSuffixes)
	}
	if policy.AllowIPLiterals {
		t.Error("expected allow_ip_literals=false")
	}
}

func TestLoad_SSRF_InvalidRoutePolicyRef_Fails(t *testing.T) {
	// Clear ambient env override so the route-policy validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `
[outbound_http.ssrf]
mode = "strict"
route_policy = "nonexistent"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error for invalid route_policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("expected error mentioning policy name, got: %v", err)
	}
}

func TestLoad_SSRF_StrictMode_RejectsOff(t *testing.T) {
	// Clear ambient env override so the strict-mode guardrail path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() + configfixture.SSRFOff()
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: mode=strict must reject ssrf.mode=off")
	}
	if !strings.Contains(err.Error(), "mode=strict requires outbound_http.ssrf.mode=strict") {
		t.Errorf("expected strict+off rejection error, got: %v", err)
	}
}

func TestLoad_SSRF_StrictMode_StrictWithValidRoutePolicy_Loads(t *testing.T) {
	// Clear ambient env override so the strict + route-policy load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// strict preset satisfies strict-mode guardrails, so a valid route policy
	// under mode=strict must load without error.
	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternal("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v; strict + valid route policy must load cleanly", err)
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("expected outbound_http.ssrf.mode %q, got %q", "strict", cfg.OutboundHTTP.SSRF.Mode)
	}
	if cfg.OutboundHTTP.SSRF.RoutePolicy != "internal" {
		t.Errorf("expected outbound_http.ssrf.route_policy %q, got %q", "internal", cfg.OutboundHTTP.SSRF.RoutePolicy)
	}
}

func TestLoad_SSRF_RoutePolicyWithIPLiterals_Fails(t *testing.T) {
	// Clear ambient env override so the IP-literal validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalIPLiteralsTrue("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: allow_ip_literals=true forbidden for active route policy")
	}
	if !strings.Contains(err.Error(), "allow_ip_literals=false") {
		t.Errorf("expected allow_ip_literals error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyWithCatchAllCIDR_Fails(t *testing.T) {
	// Clear ambient env override so the catch-all CIDR validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("catchall") +
		configfixture.RoutePolicyCatchAll("catchall")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: catch-all CIDR 0.0.0.0/0 forbidden for active route policy")
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("expected catch-all CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyEmptyCIDRs_Fails(t *testing.T) {
	// Clear ambient env override so the empty-CIDR validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("internal") + `
[outbound_http.ssrf.route_policies.internal]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = []
allowed_ports = [8080]
allow_ip_literals = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: empty allow_private_cidrs forbidden for active route policy")
	}
	if !strings.Contains(err.Error(), "allow_private_cidrs") {
		t.Errorf("expected allow_private_cidrs error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyEmptyAllowedPorts_Fails(t *testing.T) {
	// Clear ambient env override so the empty-ports validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("internal") + `
[outbound_http.ssrf.route_policies.internal]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = []
allow_ip_literals = false
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: empty allowed_ports forbidden for active route policy")
	}
	if !strings.Contains(err.Error(), "allowed_ports") {
		t.Errorf("expected allowed_ports error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyMissingHostSuffixes_Fails(t *testing.T) {
	// Clear ambient env override so the missing-suffix validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("minimal") +
		configfixture.RoutePolicyMinimalNoSuffixes("minimal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: empty allow_private_host_suffixes forbidden for active route policy")
	}
	if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
		t.Errorf("expected host suffixes error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyWithInvalidCIDR_Fails(t *testing.T) {
	// Clear ambient env override so the invalid-CIDR validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := configfixture.StrictModeBase() +
		configfixture.SSRFStrictWithPolicy("internal") +
		configfixture.RoutePolicyInternalInvalidCIDR("internal")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected error: invalid CIDR in allow_private_cidrs should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("expected invalid CIDR error, got: %v", err)
	}
}

func TestLoad_SSRF_RoutePolicyWithInvalidPort_Fails(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		wantContain string
	}{
		{
			name:        "port zero",
			port:        "0",
			wantContain: "invalid port",
		},
		{
			name:        "port above max",
			port:        "65536",
			wantContain: "invalid port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear ambient env override so the invalid-port validation path is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")

			tomlContent := configfixture.StrictModeBase() +
				configfixture.SSRFStrictWithPolicy("internal") +
				configfixture.RoutePolicyInternalWithPort("internal", tc.port)
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatalf("expected error for port %s: should be rejected as out of range", tc.port)
			}
			if !strings.Contains(err.Error(), tc.wantContain) {
				t.Errorf("expected %q in error, got: %v", tc.wantContain, err)
			}
		})
	}
}

func TestSSRFRoutePolicy_BlankHostSuffix(t *testing.T) {
	tests := []struct {
		name     string
		suffixes string
	}{
		{"empty string entry", `[""]`},
		{"whitespace-only entry", `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear ambient env override so the blank-suffix validation path is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.toml")
			tomlContent := `mode = "strict"

[outbound_http.ssrf]
route_policy = "myp"

[outbound_http.ssrf.route_policies.myp]
allow_private_host_suffixes = ` + tt.suffixes + `
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`
			if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}

			_, err := config.Load(config.LoaderOptions{ConfigPath: configPath})
			if err == nil {
				t.Fatal("expected error for blank entry in allow_private_host_suffixes")
			}
			if !strings.Contains(err.Error(), "allow_private_host_suffixes") {
				t.Errorf("expected error to mention allow_private_host_suffixes, got: %v", err)
			}
			if !strings.Contains(err.Error(), "active ssrf route policy") {
				t.Errorf("expected error to mention active ssrf route policy, got: %v", err)
			}
		})
	}
}
