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

func TestWireDTOsOnlyInSpec(t *testing.T) {
	wireDTOTypes := []string{
		"NewShareRequest",
		"CreateShareResponse",
		"InviteAcceptedRequest",
		"InviteAcceptedResponse",
		"WebDAVProtocol",
		"OCMErrorResponse",
	}

	var patterns []*regexp.Regexp
	for _, name := range wireDTOTypes {
		patterns = append(patterns, regexp.MustCompile(`type\s+`+name+`\s+struct\b`))
	}

	root := modroot.ModuleRoot(t)
	ocmDir := filepath.Join(root, "internal", "components", "ocm")

	if _, err := os.Stat(ocmDir); os.IsNotExist(err) {
		t.Skip("ocm package not found")
	}

	var violations []string

	err := filepath.WalkDir(ocmDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relPath, err := filepath.Rel(ocmDir, path)
		if err != nil {
			return err
		}

		if strings.HasPrefix(filepath.ToSlash(relPath), "spec/") {
			return nil
		}

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return err
		}

		content := string(data)

		fileRel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		for i, pat := range patterns {
			if locs := pat.FindAllStringIndex(content, -1); len(locs) > 0 {
				for _, loc := range locs {
					line := 1 + strings.Count(content[:loc[0]], "\n")
					violations = append(violations,
						fileRel+":"+itoa(line)+": wire DTO type "+wireDTOTypes[i]+" defined outside spec/")
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("Wire DTO struct definitions found outside internal/components/ocm/spec/ "+
			"(move them to the spec package):\n%s",
			strings.Join(violations, "\n"))
	}
}
