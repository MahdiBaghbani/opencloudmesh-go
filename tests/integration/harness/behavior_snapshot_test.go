package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotSubprocessReadinessPaths records readiness URL shapes the harness must keep.
var snapshotSubprocessReadinessPaths = []struct {
	name             string
	baseURL          string
	externalBasePath string
	want             string
}{
	{
		name:             "root mounted healthz",
		baseURL:          "http://localhost:8080",
		externalBasePath: "",
		want:             "http://localhost:8080/api/healthz",
	},
	{
		name:             "base path mounted healthz",
		baseURL:          "https://localhost:8443",
		externalBasePath: "/ocm",
		want:             "https://localhost:8443/ocm/api/healthz",
	},
}

func TestBehaviorSnapshot_HarnessWireOptionsAnchoredToSource(t *testing.T) {
	root := findProjectRoot(t)
	harnessPath := filepath.Join(root, "tests/integration/harness/harness.go")
	body, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("read harness source: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`app.BootstrapDeps(cfg, logger, app.WireOptions{`,
		`FastAuth:                true,`,
		`SkipCrypto:              true,`,
		`SkipPeerTrust:           true,`,
		`SkipSignatureMiddleware: true,`,
		`SSRF:               config.SSRFConfig{Mode: "off"},`,
		`SSRFMode:           "off",`,
		`TimeoutMS:          5000,`,
		`ConnectTimeoutMS:   2000,`,
		`MaxRedirects:       1,`,
		`MaxResponseBytes:   1048576,`,
		`InsecureSkipVerify: true,`,
		`SkipDiscoveryCache: true,`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("harness bootstrap WireOptions source anchor missing %q", needle)
		}
	}
}

func TestBehaviorSnapshot_SubprocessReadinessPaths(t *testing.T) {
	for _, tc := range snapshotSubprocessReadinessPaths {
		t.Run(tc.name, func(t *testing.T) {
			got := healthEndpointURL(tc.baseURL, tc.externalBasePath)
			if got != tc.want {
				t.Fatalf("healthEndpointURL(%q, %q) = %q, want %q",
					tc.baseURL, tc.externalBasePath, got, tc.want)
			}
		})
	}
}

func TestBehaviorSnapshot_SubprocessBinaryStartupExpectations(t *testing.T) {
	root := findProjectRoot(t)
	subprocessPath := filepath.Join(root, "tests/integration/harness/subprocess.go")
	body, err := os.ReadFile(subprocessPath)
	if err != nil {
		t.Fatalf("read subprocess harness: %v", err)
	}
	text := string(body)
	for _, needle := range []string{
		`exec.Command("go", "build", "-o", binaryPath, "./cmd/opencloudmesh-go")`,
		`CGO_ENABLED=0`,
		`exec.Command(binaryPath, "--config", configPath)`,
		"loadEffectiveSubprocessConfig",
		"waitForServerReady(healthEndpointURL(baseURL, finalCfg.ExternalBasePath), 10*time.Second)",
		"Process.Signal(os.Interrupt)",
		"time.After(5 * time.Second)",
		"s.cmd.Process.Kill()",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("subprocess startup expectation missing %q", needle)
		}
	}
}
