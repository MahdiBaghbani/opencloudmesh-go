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

// peerMappingAllowlist lists intentional PeerMapping* successor file paths.
var peerMappingAllowlist = []string{
	"internal/platform/config/peer_mapping.go",
	"internal/platform/config/peer_mapping_test.go",
	"internal/components/ocm/policy/peer_mapping.go",
	"internal/components/ocm/policy/peer_mapping_test.go",
	"internal/platform/config/config.go",
	"internal/platform/config/loader.go",
	"internal/platform/config/overlay.go",
}

// bannedTokens are residue identifiers that must not return.
var bannedTokens = []string{
	"PeerCompat",
	"PeerProfile",
	"compatibility_scope",
	"RuntimePolicy",
	"OpenCloudMeshPolicy",
	"/ocm-provider",
	"draft-cavage",
	"DraftCavage",
	"global_enforce",
	"EndpointNotifications",
}

var peerMappingIdent = regexp.MustCompile(`PeerMapping\w*`)

func TestResolvedFindings_BanList(t *testing.T) {
	root := modroot.ModuleRoot(t)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/architecture/resolved_findings_test.go" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)

		for _, token := range bannedTokens {
			if strings.Contains(content, token) {
				violations = append(violations, rel+": banned residue "+token)
			}
		}

		for _, match := range peerMappingIdent.FindAllString(content, -1) {
			if peerMappingAllowed(match, rel) {
				continue
			}
			violations = append(violations, rel+": banned PeerMapping identifier "+match)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Ban-list regressions:\n%s", strings.Join(violations, "\n"))
	}
}

func TestResolvedFindings_PeerMappingAllowlistPopulated(t *testing.T) {
	want := []string{
		"internal/platform/config/peer_mapping.go",
		"internal/platform/config/peer_mapping_test.go",
		"internal/components/ocm/policy/peer_mapping.go",
		"internal/components/ocm/policy/peer_mapping_test.go",
		"internal/platform/config/config.go",
		"internal/platform/config/loader.go",
		"internal/platform/config/overlay.go",
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
		found := false
		for _, w := range want {
			if path == w {
				found = true
				break
			}
		}
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
