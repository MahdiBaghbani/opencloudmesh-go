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

// peerMappingAllowlist lists intentional PeerMapping* successor paths or
// identifiers. Empty until P5 introduces PeerMapping types.
var peerMappingAllowlist = []string{}

// section3BannedTokens are Audit Sec 3 residue identifiers that must not return.
var section3BannedTokens = []string{
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

func TestResolvedFindings_Section3BanList(t *testing.T) {
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

		for _, token := range section3BannedTokens {
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
		t.Fatalf("Section 3 ban-list regressions:\n%s", strings.Join(violations, "\n"))
	}
}

func TestResolvedFindings_PeerMappingAllowlistEmpty(t *testing.T) {
	if len(peerMappingAllowlist) != 0 {
		t.Fatalf("PeerMapping allowlist must stay empty until P5; got %v", peerMappingAllowlist)
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
