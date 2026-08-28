// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

// peerMappingAllowlist lists intentional PeerMapping* successor file paths.
var peerMappingAllowlist = []string{
	"internal/components/ocm/discovery/resolve/inputs.go",
	"internal/components/ocm/discovery/resolve/resolve.go",
	"internal/components/ocm/discovery/resolve/resolve_routes_test.go",
	"internal/components/ocm/discovery/resolve/resolve_test.go",
	"internal/components/ocm/policy/compiler.go",
	"internal/components/ocm/policy/compiler_test.go",
	"internal/components/ocm/policy/peer_mapping.go",
	"internal/components/ocm/policy/peer_mapping_overlay_test.go",
	"internal/components/ocm/policy/peer_mapping_test.go",
	"internal/components/ocm/shares/incoming/handler.go",
	"internal/components/ocm/shares/incoming/handler_fixtures_test.go",
	"internal/components/ocm/shares/incoming/handler_logs_test.go",
	"internal/components/ocm/shares/incoming/handler_peer_admission_test.go",
	"internal/platform/config/config.go",
	"internal/platform/config/loader.go",
	"internal/platform/config/loader_compatibility_scope_test.go",
	"internal/platform/config/loader_peer_mapping.go",
	"internal/platform/config/overlay.go",
	"internal/platform/config/overlay_apply.go",
	"internal/platform/config/peer_mapping.go",
	"internal/platform/config/peer_mapping_test.go",
	"internal/services/ocm/inputs.go",
	"internal/services/ocm/ocm.go",
	"internal/wiring/resolve_inputs.go",
	"internal/wiring/services.go",
}

// bannedTokens are legacy identifiers that must not return in the tree.
var bannedTokens = []string{
	// PeerCompat was the old PascalCase type/name; TOML key peer_compat remains.
	"PeerCompat",
	// PeerProfile was a proposed rename for ResolveFacts; keep the retired name out of the tree.
	"PeerProfile",
	"RuntimePolicy",
	"OpenCloudMeshPolicy",
	"/ocm-provider",
	"draft-cavage",
	"DraftCavage",
	"global_enforce",
	"ErrInvalidStartBody",
	"IncrementStatsAggregate",
	"incrementStatsAggregateDB",
	"insertStatsRawAndAggregate",
	"sessionContrib",
	"SetSessionContribute",
	"clearSessionContribute",
}

var peerMappingIdent = regexp.MustCompile(`PeerMapping\w*`)

func TestResolvedFindings_BanList(t *testing.T) {
	t.Parallel()
	root := modroot.ModuleRoot(t)

	violations, err := scanBannedIdentifiers(root)
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("Retired identifier regressions:\n%s", strings.Join(violations, "\n"))
	}
}

// scanBannedIdentifiers walks root and collects retired-identifier violations
// from Go files.
func scanBannedIdentifiers(root string) ([]string, error) {
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return skipHeavyDir(d)
		}

		fileViolations, err := scanFileForBannedIdentifiers(root, path)
		if err != nil {
			return err
		}

		violations = append(violations, fileViolations...)

		return nil
	})
	if err != nil {
		return violations, fmt.Errorf("architecture: resolve findings: %w", err)
	}

	return violations, nil
}

// skipHeavyDir prunes directories that never carry first-party Go sources.
func skipHeavyDir(d fs.DirEntry) error {
	name := d.Name()
	if name == ".git" || name == "vendor" || name == "node_modules" {
		return filepath.SkipDir
	}

	return nil
}

// scanFileForBannedIdentifiers reports retired identifiers in one Go file.
func scanFileForBannedIdentifiers(root, path string) ([]string, error) {
	if !strings.HasSuffix(path, ".go") {
		return nil, nil
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, fmt.Errorf("architecture: resolve findings: %w", err)
	}

	rel = filepath.ToSlash(rel)
	if rel == "internal/architecture/resolved_findings_test.go" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("architecture: resolve findings: %w", err)
	}

	return bannedIdentifierViolations(string(data), rel), nil
}

// bannedIdentifierViolations matches the ban list and the PeerMapping guard
// against one file's content.
func bannedIdentifierViolations(content, rel string) []string {
	var violations []string

	for _, token := range bannedTokens {
		if strings.Contains(content, token) {
			violations = append(violations, rel+": retired identifier "+token)
		}
	}

	for _, match := range peerMappingIdent.FindAllString(content, -1) {
		if peerMappingAllowed(match, rel) {
			continue
		}

		violations = append(violations, rel+": banned PeerMapping identifier "+match)
	}

	return violations
}

func TestResolvedFindings_PeerMappingAllowlistPopulated(t *testing.T) {
	t.Parallel()

	want := []string{
		"internal/components/ocm/discovery/resolve/inputs.go",
		"internal/components/ocm/discovery/resolve/resolve.go",
		"internal/components/ocm/discovery/resolve/resolve_routes_test.go",
		"internal/components/ocm/discovery/resolve/resolve_test.go",
		"internal/components/ocm/policy/compiler.go",
		"internal/components/ocm/policy/compiler_test.go",
		"internal/components/ocm/policy/peer_mapping.go",
		"internal/components/ocm/policy/peer_mapping_overlay_test.go",
		"internal/components/ocm/policy/peer_mapping_test.go",
		"internal/components/ocm/shares/incoming/handler.go",
		"internal/components/ocm/shares/incoming/handler_fixtures_test.go",
		"internal/components/ocm/shares/incoming/handler_logs_test.go",
		"internal/components/ocm/shares/incoming/handler_peer_admission_test.go",
		"internal/platform/config/config.go",
		"internal/platform/config/loader.go",
		"internal/platform/config/loader_compatibility_scope_test.go",
		"internal/platform/config/loader_peer_mapping.go",
		"internal/platform/config/overlay.go",
		"internal/platform/config/overlay_apply.go",
		"internal/platform/config/peer_mapping.go",
		"internal/platform/config/peer_mapping_test.go",
		"internal/services/ocm/inputs.go",
		"internal/services/ocm/ocm.go",
		"internal/wiring/resolve_inputs.go",
		"internal/wiring/services.go",
	}

	if len(peerMappingAllowlist) == 0 {
		t.Fatal("PeerMapping allowlist must be non-empty")
	}

	if len(peerMappingAllowlist) != len(want) {
		t.Fatalf("PeerMapping allowlist length = %d, want %d; got %v",
			len(peerMappingAllowlist), len(want), peerMappingAllowlist)
	}

	got := make(map[string]struct{}, len(peerMappingAllowlist))
	for _, path := range peerMappingAllowlist {
		got[path] = struct{}{}
	}

	for _, path := range want {
		if _, ok := got[path]; !ok {
			t.Errorf("PeerMapping allowlist missing %q", path)
		}
	}

	for path := range got {
		found := slices.Contains(want, path)

		if !found {
			t.Errorf("PeerMapping allowlist has unexpected %q", path)
		}
	}
}

func peerMappingAllowed(ident, rel string) bool {
	for _, allow := range peerMappingAllowlist {
		if allow == ident || allow == rel || strings.Contains(rel, allow) {
			return true
		}
	}

	return false
}

func TestRFC9421Conformance(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{name: "tag-based identification", run: assertTagBasedIdentification},
		{name: "label-free identification", run: assertLabelFreeIdentification},
		{name: "ReasonUnsigned for missing tag", run: assertReasonUnsigned},
		{name: "tag integrity", run: assertTagIntegrity},
		{name: "golden output", run: assertGoldenOutput},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

func assertTagBasedIdentification(t *testing.T) {
	t.Helper()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519", JWKAlg: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("tag-based identification failed: %v", result.Error)
	}
}

func assertLabelFreeIdentification(t *testing.T) {
	t.Helper()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	signOpts := crypto.DefaultRFC9421Options()
	signOpts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signOpts.Label = "peerlabel"
	signer := crypto.NewRFC9421SignerWithOptions(km, signOpts)

	verifyOpts := crypto.DefaultRFC9421Options()
	verifyOpts.Now = signOpts.Now
	verifier := crypto.NewRFC9421VerifierWithOptions(verifyOpts)

	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	if !strings.HasPrefix(req.Header.Get("Signature-Input"), "peerlabel=") {
		t.Fatalf("Signature-Input = %q, want peerlabel= prefix", req.Header.Get("Signature-Input"))
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519", JWKAlg: "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("label-free identification failed: %v", result.Error)
	}
}

func assertReasonUnsigned(t *testing.T) {
	t.Helper()

	verifier := crypto.NewRFC9421Verifier()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("Date", "Fri, 16 Jan 2026 13:37:00 GMT")
	req.Header.Set("Signature-Input", `sig1=("@method" "@target-uri" "date");created=1730815200;keyid="example.com#key1";alg="ed25519"`)
	req.Header.Set("Signature", "sig1=:AAAA:")

	result := verifier.VerifyRequest(req, nil, func(string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{}, errors.New("should not fetch key")
	})
	if result.Verified {
		t.Fatal("expected verification failure")
	}

	if result.Reason != crypto.ReasonUnsigned {
		t.Fatalf("Reason = %q, want %q", result.Reason, crypto.ReasonUnsigned)
	}
}

func assertTagIntegrity(t *testing.T) {
	t.Helper()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421VerifierWithOptions(opts)

	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	req.Header.Set("Signature-Input", strings.Replace(req.Header.Get("Signature-Input"), `tag="`+sigparams.SignatureTagOCM+`"`, `tag="other"`, 1))

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		return sigalg.ResolvedPublicKey{
			KeyID: keyID, PublicKey: km.GetSigningKey().PublicKey,
			JWKKty: "OKP", JWKCrv: "Ed25519", JWKAlg: "Ed25519",
		}, nil
	})
	if result.Verified {
		t.Fatal("expected verification failure when tag is changed")
	}
}

func assertGoldenOutput(t *testing.T) {
	t.Helper()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	opts := crypto.DefaultRFC9421Options()
	opts.Now = func() time.Time { return time.Unix(1_730_815_200, 0) }
	signer := crypto.NewRFC9421SignerWithOptions(km, opts)

	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")

	goldenRe := regexp.MustCompile(
		`^ocm=\("@method" "@target-uri" "content-digest" "content-length"\);created=1730815200;keyid="[^"]+";alg="ed25519";tag="ocm"$`,
	)
	if !goldenRe.MatchString(sigInput) {
		t.Fatalf("Signature-Input = %q, does not match golden default pattern", sigInput)
	}
}
