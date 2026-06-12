package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacySingletonPatterns bans removed singleton/bootstrap surfaces from production code.
var legacySingletonPatterns = []string{
	"/internal/platform/deps\"",
	"/internal/platform/app\"",
	"deps.GetDeps(",
	"deps.SetDeps(",
	"deps.ResetDeps(",
	"BootstrapDeps(",
}

// legacySingletonAllowlist paths may reference legacy names only in comments or
// guard definitions; production wiring must not import or call them.
var legacySingletonAllowlist = map[string]struct{}{}

func TestNoLegacySingletonSurfacesInProductionCode(t *testing.T) {
	repoRoot := findRepoRoot(t)
	var violations []string

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
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

		relPath, _ := filepath.Rel(repoRoot, path)
		relPath = filepath.ToSlash(relPath)
		if strings.HasPrefix(relPath, "internal/guards/") {
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
	repoRoot := findRepoRoot(t)
	for _, rel := range []string{
		"internal/platform/app",
		"internal/platform/deps",
	} {
		abs := filepath.Join(repoRoot, rel)
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
			relPath, _ := filepath.Rel(repoRoot, path)
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
