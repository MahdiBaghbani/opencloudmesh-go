package app_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
)

// snapshotHarnessWireOptions is the in-process integration harness baseline from
// tests/integration/harness/harness.go StartTestServerWithConfig.
var snapshotHarnessWireOptions = app.WireOptions{
	FastAuth:                true,
	SkipCrypto:              true,
	SkipPeerTrust:           true,
	SkipSignatureMiddleware: true,
	OutboundOverride: &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		SSRFMode:           "off",
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true,
	},
	SkipDiscoveryCache: true,
}

// snapshotProductionWireOptions is the main.go zero-value bootstrap path.
var snapshotProductionWireOptions = app.WireOptions{}

type unprotectedSnapshot struct {
	service string
	paths   []string
}

// snapshotUnprotectedSets captures default DevConfig Unprotected() declarations.
var snapshotUnprotectedSets = []unprotectedSnapshot{
	{service: "wellknown", paths: []string{
		"/.well-known/ocm", "/.well-known/ocm/", "/ocm-provider", "/ocm-provider/",
	}},
	{service: "ocm", paths: []string{"/shares", "/notifications", "/invite-accepted", "/token"}},
	{service: "ocmaux", paths: []string{"/federations", "/discover"}},
	{service: "api", paths: []string{"/healthz", "/auth/login"}},
	{service: "ui", paths: []string{"/login"}},
	{service: "webdav", paths: []string{"/ocm"}},
}

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
		contains: []string{"app.BootstrapDeps", "service.CoreServices", "deps.GetDeps"},
	},
	{
		seam:     "harness bootstrap parity",
		path:     "tests/integration/harness/harness.go",
		contains: []string{"app.BootstrapDeps", "service.CoreServices", "healthEndpointURL"},
	},
	{
		seam:     "subprocess binary startup",
		path:     "tests/integration/harness/subprocess.go",
		contains: []string{"BuildBinary", "StartSubprocessServer", "loadEffectiveSubprocessConfig"},
	},
}

func TestBehaviorSnapshot_HarnessWireOptionsMatchesHelper(t *testing.T) {
	if !reflect.DeepEqual(harnessWireOptions(), snapshotHarnessWireOptions) {
		t.Fatalf("harnessWireOptions() = %+v, want snapshot %+v",
			harnessWireOptions(), snapshotHarnessWireOptions)
	}
}

func TestBehaviorSnapshot_ProductionZeroValueMainAnchor(t *testing.T) {
	root := moduleRoot(t)
	mainPath := filepath.Join(root, "cmd/opencloudmesh-go/main.go")
	body, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(body)

	for _, needle := range []string{
		`result, err := app.BootstrapDeps(cfg, logger, app.WireOptions{})`,
		`app.BootstrapDeps(cfg, logger, app.WireOptions{})`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("production zero-value wiring path missing %q", needle)
		}
	}
}

func TestBehaviorSnapshot_ProductionZeroValueStruct(t *testing.T) {
	var got app.WireOptions
	if !reflect.DeepEqual(got, snapshotProductionWireOptions) {
		t.Fatalf("zero WireOptions = %+v, want snapshot %+v", got, snapshotProductionWireOptions)
	}
	if got.FastAuth || got.SkipCrypto || got.SkipPeerTrust ||
		got.SkipSignatureMiddleware || got.SkipDiscoveryCache || got.OutboundOverride != nil {
		t.Fatalf("production WireOptions must remain zero-valued, got %+v", got)
	}
}

func TestBehaviorSnapshot_RegisteredServicesCoverCoreServices(t *testing.T) {
	registered := service.RegisteredServices()
	for _, name := range service.CoreServices {
		if service.Get(name) == nil {
			t.Errorf("core service %q is not registered", name)
		}
		if !slices.Contains(registered, name) {
			t.Errorf("RegisteredServices() missing core service %q", name)
		}
	}
}

func TestBehaviorSnapshot_UnprotectedSets(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://snapshot.test"
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"

	deps.ResetDeps()
	t.Cleanup(deps.ResetDeps)

	_, err := app.BootstrapDeps(cfg, discardLogger(), harnessWireOptions())
	if err != nil {
		t.Fatalf("BootstrapDeps failed: %v", err)
	}

	log := discardLogger()
	for _, want := range snapshotUnprotectedSets {
		t.Run(want.service, func(t *testing.T) {
			newFn := service.Get(want.service)
			if newFn == nil {
				t.Fatalf("service %q not registered", want.service)
			}
			svcCfg := cfg.BuildServiceConfig(want.service)
			if svcCfg == nil {
				svcCfg = map[string]any{}
			}
			svc, err := newFn(svcCfg, log)
			if err != nil {
				t.Fatalf("construct %q: %v", want.service, err)
			}
			t.Cleanup(func() { _ = svc.Close() })

			got := append([]string(nil), svc.Unprotected()...)
			if !reflect.DeepEqual(got, want.paths) {
				t.Fatalf("Unprotected() = %v, want snapshot %v", got, want.paths)
			}
		})
	}
}

func TestBehaviorSnapshot_LegacyCutoverInventoryAnchors(t *testing.T) {
	root := moduleRoot(t)
	for _, anchor := range legacyCutoverInventory {
		t.Run(anchor.seam, func(t *testing.T) {
			target := filepath.Join(root, anchor.path)
			info, err := os.Stat(target)
			if err != nil {
				t.Fatalf("anchor path missing: %s (%v)", anchor.path, err)
			}
			if info.IsDir() {
				t.Fatalf("anchor path %s is a directory; inventory anchors must name files (or add explicit directory anchor support)", anchor.path)
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

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}

// Ensure legacyCutoverInventory size matches the named guard constant.
func TestBehaviorSnapshot_LegacyCutoverInventoryNonEmpty(t *testing.T) {
	got := len(legacyCutoverInventory)
	if got != legacyCutoverInventoryExpectedCount {
		t.Fatalf("legacy cutover inventory count = %d, want exactly %d (update legacyCutoverInventoryExpectedCount when changing anchors)", got, legacyCutoverInventoryExpectedCount)
	}
}
