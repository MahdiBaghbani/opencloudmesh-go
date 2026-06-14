package architecture

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoProfileRegistryOutsidePeercompat(t *testing.T) {
	root := modroot.ModuleRoot(t)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		relPath = filepath.ToSlash(relPath)
		if strings.Contains(relPath, "/internal/components/ocm/peercompat/") ||
			strings.HasPrefix(relPath, "internal/components/ocm/peercompat/") {
			return nil
		}
		if strings.Contains(relPath, "/internal/architecture/") ||
			strings.HasPrefix(relPath, "internal/architecture/") {
			return nil
		}
		if strings.Contains(relPath, "/internal/testsupport/ocm/") ||
			strings.HasPrefix(relPath, "internal/testsupport/ocm/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "ProfileRegistry") {
			violations = append(violations, relPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("found ProfileRegistry references outside peercompat:\n%s", strings.Join(violations, "\n"))
	}
}

func TestNoRawCompatibilityHelpersOutsidePeercompat(t *testing.T) {
	root := modroot.ModuleRoot(t)
	pattern := regexp.MustCompile(`\.(HasQuirk|GetTokenExchangeGrantType|IsBasicAuthPatternAllowed)\(`)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		relPath = filepath.ToSlash(relPath)
		if strings.Contains(relPath, "/internal/components/ocm/peercompat/") ||
			strings.HasPrefix(relPath, "internal/components/ocm/peercompat/") {
			return nil
		}
		if strings.Contains(relPath, "/internal/architecture/") ||
			strings.HasPrefix(relPath, "internal/architecture/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		if locs := pattern.FindAllStringIndex(content, -1); len(locs) > 0 {
			for _, loc := range locs {
				line := 1 + strings.Count(content[:loc[0]], "\n")
				violations = append(violations, relPath+":"+itoa(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("found raw compatibility helper calls outside peercompat:\n%s", strings.Join(violations, "\n"))
	}
}

func TestNoAdHocPeerOriginSchemeInApprovedCallSites(t *testing.T) {
	root := modroot.ModuleRoot(t)
	targets := []string{
		"internal/components/ocm/access/remote.go",
		"internal/components/ocm/discovery/peer_adapter.go",
		"internal/components/ocm/shares/incoming/handler.go",
		"internal/components/api/outgoing/shares/handler.go",
		"internal/components/ocm/notifications/outgoing/client.go",
		"internal/components/api/inbox/invites/handler.go",
	}

	var violations []string
	for _, relPath := range targets {
		fullPath := filepath.Join(root, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("read %s failed: %v", relPath, err)
		}
		content := string(data)
		if strings.Contains(content, `"://"`) ||
			strings.Contains(content, `"https://"`) ||
			strings.Contains(content, `"http://"`) {
			violations = append(violations, relPath)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("found ad hoc scheme assembly in peer-origin call sites:\n%s", strings.Join(violations, "\n"))
	}
}

var allowUnsignedDiscoveryPattern = regexp.MustCompile(`[^.]allow_unsigned_discovery`)

func TestAllowUnsignedDiscoveryLiveCarrierPaths(t *testing.T) {
	root := modroot.ModuleRoot(t)
	allowedCarrierFiles := map[string]struct{}{
		"internal/platform/config/config.go":                        {},
		"internal/components/ocm/peercompat/profiles.go":            {},
		"internal/components/ocm/peercompat/signature_decisions.go": {},
	}

	var violations []string
	foundLiveCarrier := false

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		relPath = filepath.ToSlash(relPath)
		if strings.Contains(relPath, "/internal/architecture/") ||
			strings.HasPrefix(relPath, "internal/architecture/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !allowUnsignedDiscoveryPattern.Match(data) {
			return nil
		}

		if _, ok := allowedCarrierFiles[relPath]; ok {
			foundLiveCarrier = true
			return nil
		}
		violations = append(violations, relPath)
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("found allow_unsigned_discovery outside approved live carriers:\n%s", strings.Join(violations, "\n"))
	}
	if !foundLiveCarrier {
		t.Fatal("no live allow_unsigned_discovery carrier found in approved paths")
	}
}
