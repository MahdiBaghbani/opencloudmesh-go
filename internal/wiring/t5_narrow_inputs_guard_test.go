package wiring_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestT5_NoServiceImportsDepsPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)
	violations := findProductionImportSuffix(t, root, []string{"internal/services"}, "/platform/deps")
	if len(violations) > 0 {
		t.Fatalf("services must not import platform/deps; violations: %s", strings.Join(violations, ", "))
	}
}

func TestT5_NoInterceptorImportsDepsPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)
	violations := findProductionImportSuffix(t, root, []string{"internal/interceptors"}, "/platform/deps")
	if len(violations) > 0 {
		t.Fatalf("interceptors must not import platform/deps; violations: %s", strings.Join(violations, ", "))
	}
}

func TestT5_NoServiceImportsWiringPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)
	violations := findProductionImportSuffix(t, root, []string{"internal/services"}, "/internal/wiring")
	if len(violations) > 0 {
		t.Fatalf("services must not import internal/wiring; violations: %s", strings.Join(violations, ", "))
	}
}

func TestT5_NoInterceptorImportsWiringPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)
	violations := findProductionImportSuffix(t, root, []string{"internal/interceptors"}, "/internal/wiring")
	if len(violations) > 0 {
		t.Fatalf("interceptors must not import internal/wiring; violations: %s", strings.Join(violations, ", "))
	}
}

func TestT5_ServerDoesNotUseDepsSingleton(t *testing.T) {
	root := modroot.ModuleRoot(t)
	serverDir := filepath.Join(root, "internal/platform/http/server")
	for _, name := range []string{"server.go", "routes.go"} {
		body, err := os.ReadFile(filepath.Join(serverDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(body)
		if strings.Contains(text, "deps.GetDeps") {
			t.Fatalf("%s must not call deps.GetDeps", name)
		}
	}
}

func TestT5_ServerDoesNotRebuildSigner(t *testing.T) {
	root := modroot.ModuleRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal/platform/http/server/server.go"))
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "NewRFC9421Signer") || strings.Contains(text, "KeyManager") {
		t.Fatal("server.go must not rebuild signer from KeyManager")
	}
}

func TestT5_ResolvePackageUsesResolveInputs(t *testing.T) {
	root := modroot.ModuleRoot(t)
	resolveDir := filepath.Join(root, "internal/components/ocm/discovery/resolve")
	resolveGo, err := os.ReadFile(filepath.Join(resolveDir, "resolve.go"))
	if err != nil {
		t.Fatalf("read resolve.go: %v", err)
	}
	if strings.Contains(string(resolveGo), `"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"`) {
		t.Fatal("resolve.go must not import platform/deps")
	}
	if !strings.Contains(string(resolveGo), "func Resolve(c *ProviderConfig, rawOCMProvider map[string]any, in ResolveInputs)") {
		t.Fatal("Resolve must accept ResolveInputs instead of deps.Deps")
	}
	inputsGo, err := os.ReadFile(filepath.Join(resolveDir, "inputs.go"))
	if err != nil {
		t.Fatalf("read inputs.go: %v", err)
	}
	if !strings.Contains(string(inputsGo), "type ResolveInputs struct") {
		t.Fatal("resolve package must define ResolveInputs in inputs.go")
	}
}

func TestT5_SessionAuthGateRelocatedFromPlatformHTTPAuth(t *testing.T) {
	root := modroot.ModuleRoot(t)
	authPath := filepath.Join(root, "internal/platform/http/auth/auth.go")
	if _, err := os.Stat(authPath); err == nil {
		body, readErr := os.ReadFile(authPath)
		if readErr != nil {
			t.Fatalf("read auth.go: %v", readErr)
		}
		if strings.Contains(string(body), "func NewAuthGate") {
			t.Fatal("platform/http/auth must not own NewAuthGate after relocation")
		}
	}
	gatePath := filepath.Join(root, "internal/components/identity/sessiongate/sessiongate.go")
	if _, err := os.Stat(gatePath); err != nil {
		t.Fatalf("session auth gate must live in sessiongate: %v", err)
	}
}

func TestT5_InboundSignatureOwnedByOCM(t *testing.T) {
	root := modroot.ModuleRoot(t)
	sigDir := filepath.Join(root, "internal/components/ocm/inbound/signature")
	if _, err := os.Stat(sigDir); err != nil {
		t.Fatalf("inbound signature package missing: %v", err)
	}
	cryptoMW := filepath.Join(root, "internal/platform/crypto/middleware.go")
	if _, err := os.Stat(cryptoMW); err == nil {
		body, readErr := os.ReadFile(cryptoMW)
		if readErr != nil {
			t.Fatalf("read middleware.go: %v", readErr)
		}
		if strings.Contains(string(body), "type SignatureMiddleware struct") {
			t.Fatal("SignatureMiddleware must not remain in platform/crypto")
		}
	}
}

func TestT5_ServerDepsDefinedInServerPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)
	depsGo := filepath.Join(root, "internal/platform/http/server/deps.go")
	body, err := os.ReadFile(depsGo)
	if err != nil {
		t.Fatalf("read server/deps.go: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "type ServerDeps struct") {
		t.Fatal("server package must define ServerDeps")
	}
	if !strings.Contains(text, "AuthGate") {
		t.Fatal("ServerDeps must include injected auth gate")
	}
	if strings.Contains(text, "Signer") {
		t.Fatal("ServerDeps must not include signer; outbound signing uses service-level inputs")
	}
}

func TestT5_WiringBuildsServerDeps(t *testing.T) {
	root := modroot.ModuleRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal/wiring/server_deps.go"))
	if err != nil {
		t.Fatalf("read wiring/server_deps.go: %v", err)
	}
	if !strings.Contains(string(body), "func BuildServerDeps") {
		t.Fatal("wiring must expose BuildServerDeps")
	}
}
