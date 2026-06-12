package app_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"
)

// legacyCutoverAnchor names a pre-rewrite seam that later Q5 waves must either
// preserve or explicitly replace. Path is repo-relative from module root.
type legacyCutoverAnchor struct {
	seam     string
	path     string
	contains []string
}

// legacyCutoverInventoryExpectedCount must match len(legacyCutoverInventory).
// Bump intentionally when adding or removing cutover anchors.
const legacyCutoverInventoryExpectedCount = 12

// legacyCutoverInventory is the durable Q5 T0 cutover guard list.
var legacyCutoverInventory = []legacyCutoverAnchor{
	{
		seam:     "deps singleton GetDeps/SetDeps/ResetDeps",
		path:     "internal/platform/deps/shareddeps.go",
		contains: []string{"func SetDeps", "func GetDeps", "func ResetDeps"},
	},
	{
		seam:     "bootstrap seam BootstrapDeps and WireOptions",
		path:     "internal/platform/app/bootstrap.go",
		contains: []string{"type WireOptions struct", "func BootstrapDeps", "deps.SetDeps"},
	},
	{
		seam:     "service registry Register/Get/CoreServices",
		path:     "internal/frameworks/service/registry.go",
		contains: []string{"var CoreServices", "func Register", "func Get"},
	},
	{
		seam:     "service loader blank imports",
		path:     "internal/services/loader/loader.go",
		contains: []string{"internal/services/api", "internal/services/wellknown"},
	},
	{
		seam:     "interceptor loader blank imports",
		path:     "internal/interceptors/loader/loader.go",
		contains: []string{"internal/interceptors/ratelimit"},
	},
	{
		seam: "cache driver loader blank imports",
		path: "internal/platform/cache/loader/loader.go",
		contains: []string{
			"internal/platform/cache/memory",
			"internal/platform/cache/redis",
		},
	},
	{
		seam:     "signer rebuild in server.New",
		path:     "internal/platform/http/server/server.go",
		contains: []string{"crypto.NewRFC9421Signer", "d.KeyManager"},
	},
	{
		seam:     "auth gate in setupRoutes",
		path:     "internal/platform/http/server/routes.go",
		contains: []string{"auth.NewAuthGate", "IsAuthRequired"},
	},
	{
		seam:     "inbound signature middleware wiring",
		path:     "internal/platform/app/bootstrap.go",
		contains: []string{"SignatureMiddleware", "crypto.NewSignatureMiddleware"},
	},
	{
		seam:     "main.go production bootstrap and service loop",
		path:     "cmd/opencloudmesh-go/main.go",
		contains: []string{"wiring.Build", "service.CoreServices", "deps.GetDeps"},
	},
	{
		seam:     "harness bootstrap parity",
		path:     "tests/integration/harness/harness.go",
		contains: []string{"wiring.Build", "service.CoreServices", "healthEndpointURL"},
	},
	{
		seam:     "subprocess binary startup",
		path:     "tests/integration/harness/subprocess.go",
		contains: []string{"BuildBinary", "StartSubprocessServer", "loadEffectiveSubprocessConfig"},
	},
}

func TestBehaviorSnapshot_LegacyCutoverInventoryAnchors(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	for _, anchor := range legacyCutoverInventory {
		t.Run(anchor.seam, func(t *testing.T) {
			target := filepath.Join(root, anchor.path)
			info, err := os.Stat(target)
			if err != nil {
				t.Fatalf("anchor path missing: %s (%v)", anchor.path, err)
			}
			if info.IsDir() {
				t.Fatalf("anchor path %s is a directory; inventory anchors must name files", anchor.path)
			}
			body, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("read anchor %s: %v", anchor.path, err)
			}
			text := string(body)
			for _, needle := range anchor.contains {
				if !strings.Contains(text, needle) {
					t.Fatalf("anchor %q missing %q in %s", anchor.seam, needle, anchor.path)
				}
			}
		})
	}
}

// Ensure legacyCutoverInventory size matches the named guard constant.
func TestBehaviorSnapshot_LegacyCutoverInventoryNonEmpty(t *testing.T) {
	got := len(legacyCutoverInventory)
	if got != legacyCutoverInventoryExpectedCount {
		t.Fatalf("legacy cutover inventory count = %d, want exactly %d (update legacyCutoverInventoryExpectedCount when changing anchors)", got, legacyCutoverInventoryExpectedCount)
	}
}
