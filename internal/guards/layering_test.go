package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOCMPackagesDoNotImportAPI enforces the layering invariant that OCM domain
// packages must not import API packages. The dependency direction must be
// api -> ocm, never ocm -> api.
//
// This prevents OCM domain models from coupling to API view models or HTTP
// handler infrastructure.
func TestOCMPackagesDoNotImportAPI(t *testing.T) {
	repoRoot := findRepoRoot(t)
	ocmDir := filepath.Join(repoRoot, "internal", "components", "ocm")

	if _, err := os.Stat(ocmDir); os.IsNotExist(err) {
		t.Skip("ocm package not found")
	}

	// The forbidden import prefix: any ocm/ Go file importing an api/ package
	forbiddenImport := `"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api`

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

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		fileRel, _ := filepath.Rel(repoRoot, path)

		for i, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, forbiddenImport) {
				violations = append(violations,
					fileRel+":"+itoa(i+1)+": OCM package imports API package: "+trimmed)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("OCM packages must not import API packages (dependency flows api -> ocm, not reverse):\n%s",
			strings.Join(violations, "\n"))
	}
}
