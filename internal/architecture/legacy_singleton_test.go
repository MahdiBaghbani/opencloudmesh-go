package architecture

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

var legacySingletonPatterns = []string{
	"/internal/platform/deps\"",
	"/internal/platform/app\"",
	"deps.GetDeps(",
	"deps.SetDeps(",
	"deps.ResetDeps(",
	"BootstrapDeps(",
}

var legacySingletonAllowlist = map[string]struct{}{}

func TestNoLegacySingletonSurfacesInProductionCode(t *testing.T) {
	root := modroot.ModuleRoot(t)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		relPath, _ := filepath.Rel(root, path)
		relPath = filepath.ToSlash(relPath)
		if strings.HasPrefix(relPath, "internal/architecture/") {
			return nil
		}
		if _, ok := legacySingletonAllowlist[relPath]; ok {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, pattern := range legacySingletonPatterns {
			if strings.Contains(content, pattern) {
				violations = append(violations, relPath+": contains banned legacy pattern "+pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("legacy singleton/bootstrap residue in production code:\n%s", strings.Join(violations, "\n"))
	}
}

func TestLegacyPlatformAppAndDepsPackagesDeleted(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for _, rel := range []string{
		"internal/platform/app",
		"internal/platform/deps",
	} {
		abs := filepath.Join(root, rel)
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatalf("stat %s failed: %v", rel, err)
		}

		var goFiles []string
		err := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			relPath, _ := filepath.Rel(root, path)
			goFiles = append(goFiles, filepath.ToSlash(relPath))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s failed: %v", rel, err)
		}
		if len(goFiles) > 0 {
			t.Fatalf("legacy package %s must not contain .go files; found:\n%s",
				rel, strings.Join(goFiles, "\n"))
		}
		t.Fatalf("legacy package directory still present: %s", rel)
	}
}
