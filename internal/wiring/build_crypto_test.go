package wiring_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	apisvc "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	tswiring "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestCryptoSkip_GatesDeps(t *testing.T) {
	t.Run("SkipCrypto=true fails when code flow requires HTTP signatures", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = true
		_, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err == nil {
			t.Fatal("expected bootstrap to fail when SkipCrypto=true and code flow requires HTTP signatures")
		}
		want := "ocm: code flow requires HTTP request signatures but no signing key is configured"
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want substring %q", err.Error(), want)
		}
	})

	t.Run("SkipCrypto=true succeeds when code flow does not require HTTP signatures", func(t *testing.T) {
		cfg := config.DevConfig()
		falseVal := false
		cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures = &falseVal

		opts := harnessBuildOpts()
		opts.SkipCrypto = true
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap should succeed when requires_http_request_signatures=false and SkipCrypto=true: %v", err)
		}
		if result.Deps == nil {
			t.Fatal("Deps is nil after successful Build")
		}
		if result.Deps.CodeFlow == nil {
			t.Fatal("CodeFlow is nil; Build must populate it")
		}
		if facts := result.Deps.CodeFlow.Evaluate(); facts.RequiresHTTPRequestSignatures {
			t.Error("expected CodeFlow.Evaluate() to report RequiresHTTPRequestSignatures=false")
		}
	})

	t.Run("SkipCrypto=false with crypto enabled produces non-nil Signer", func(t *testing.T) {
		cfg := config.DevConfig()

		opts := harnessBuildOpts()
		opts.SkipCrypto = false
		result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := result.Deps
		if d.KeyManager == nil {
			t.Error("KeyManager must be non-nil when crypto is enabled and SkipCrypto=false")
		}
		if d.Signer == nil {
			t.Error("Signer must be non-nil when KeyManager is present")
		}
	})
}

func TestBuild_SignatureConfigWiresSignerOptions(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")
	keyPath := filepath.Join(dir, "signing.pem")
	tomlContent := fmt.Sprintf(`
mode = "dev"
public_origin = "http://localhost:9200"
listen_addr = "localhost:9200"

[signature]
label = "wiredlabel"
key_path = %q
`, keyPath)
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	opts := harnessBuildOpts()
	opts.SkipCrypto = false

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if result.Deps.Signer == nil {
		t.Fatal("Signer must be non-nil when crypto is enabled")
	}

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := result.Deps.Signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "wiredlabel=") {
		t.Fatalf("Signature-Input = %q, want wiredlabel= prefix from config", sigInput)
	}
	if !strings.Contains(sigInput, `;tag="ocm"`) {
		t.Fatalf("Signature-Input = %q, want OCM tag parameter", sigInput)
	}

	verifier := crypto.NewRFC9421Verifier()
	verifyResult := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		key := result.Deps.KeyManager.GetSigningKey()
		return sigalg.ResolvedPublicKey{
			KeyID:     keyID,
			Algorithm: key.Algorithm,
			PublicKey: key.PublicKey,
			JWKKty:    "OKP",
			JWKCrv:    "Ed25519",
		}, nil
	})
	if !verifyResult.Verified {
		t.Fatalf("tag-based verification failed: %v", verifyResult.Error)
	}
}

func TestBuild_IETFHarnessOptsWireFullCryptoStack(t *testing.T) {
	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), toBuildOpts(tswiring.IETFWireOptions))
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if result.Deps.KeyManager == nil {
		t.Fatal("KeyManager must be non-nil for IETF harness opts")
	}
	if result.Deps.Signer == nil {
		t.Fatal("Signer must be non-nil for IETF harness opts")
	}
	if result.Deps.SignatureMiddleware == nil {
		t.Fatal("SignatureMiddleware must be non-nil for IETF harness opts")
	}
}

func TestBuild_APIOutgoingHandlerTokenEndpointMatchesDiscoveryResolve(t *testing.T) {
	cfg := config.DevConfig()
	// Set the production discovery provider path under wellknown.ocmprovider
	// and a different aggregate route path under ocm. The wiring must use the
	// provider path, not the route path, to stay aligned with discovery.
	cfg.HTTP.Services = map[string]map[string]any{
		"wellknown": {
			"ocmprovider": map[string]any{
				"token_exchange": map[string]any{
					"path": "wellknown-token",
				},
			},
		},
		"ocm": {
			"token_exchange": map[string]any{
				"path": "ocm-token",
			},
		},
	}

	opts := harnessBuildOpts()
	opts.SkipCrypto = false

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	var rawOCMProvider map[string]any
	if wellknownSvcCfg := cfg.BuildServiceConfig("wellknown"); wellknownSvcCfg != nil {
		if om, ok := wellknownSvcCfg["ocmprovider"].(map[string]any); ok {
			rawOCMProvider = om
		}
	}
	var providerCfg resolve.ProviderConfig
	if rawOCMProvider != nil {
		if err := svccfg.Decode(rawOCMProvider, &providerCfg); err != nil {
			t.Fatalf("decode ocm provider config: %v", err)
		}
	}
	resolved := resolve.Resolve(&providerCfg, rawOCMProvider, resolve.ResolveInputs{
		LocalIdentity:     result.Deps.LocalIdentity,
		RouteOpts:         service.RouteOptsFromConfig(cfg),
		TokenExchangePath: cfg.TokenExchange.Path,
		KeyManager:        result.Deps.KeyManager,
		CodeFlow:          result.Deps.CodeFlow,
	})
	want := resolved.Params.TokenEndPoint
	if want == "" {
		t.Fatal("resolved token endpoint is empty")
	}
	if !strings.HasSuffix(want, "/wellknown-token") {
		t.Fatalf("resolved token endpoint %q did not use provider override", want)
	}

	services, err := wiring.BuildCoreServices(cfg, tslog.DiscardLogger(), result.Deps)
	if err != nil {
		t.Fatalf("BuildCoreServices failed: %v", err)
	}
	apiSvc, ok := services["api"].(*apisvc.Service)
	if !ok {
		t.Fatalf("api service is %T, not *api.Service", services["api"])
	}
	outgoingHandler := reflect.ValueOf(apiSvc).Elem().FieldByName("outgoingHandler")
	if outgoingHandler.IsNil() {
		t.Fatal("outgoing shares handler is nil")
	}
	got := outgoingHandler.Elem().FieldByName("localTokenEndPoint").String()
	if got != want {
		t.Fatalf("outgoing handler localTokenEndPoint = %q, want %q", got, want)
	}
}

func TestBuild_DefaultSignatureInputIncludesOCMTag(t *testing.T) {
	cfg := config.DevConfig()
	opts := harnessBuildOpts()
	opts.SkipCrypto = false

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if result.Deps.Signer == nil {
		t.Fatal("Signer must be non-nil when crypto is enabled")
	}

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest("POST", "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"

	if err := result.Deps.Signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "ocm=") {
		t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
	}
	if !strings.HasSuffix(sigInput, `;tag="ocm"`) {
		t.Fatalf("Signature-Input = %q, want ;tag=\"ocm\" suffix", sigInput)
	}
}
