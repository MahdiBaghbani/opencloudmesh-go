package architecture

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestOCMPackagesDoNotImportAPI(t *testing.T) {
	root := modroot.ModuleRoot(t)
	ocmDir := filepath.Join(root, "internal", "components", "ocm")

	if _, err := os.Stat(ocmDir); os.IsNotExist(err) {
		t.Skip("ocm package not found")
	}

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

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return err
		}

		content := string(data)

		fileRel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

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

func TestServicesDoNotImportDepsPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)

	violations := findProductionImportSuffix(t, root, []string{"internal/services"}, "/platform/deps")
	if len(violations) > 0 {
		t.Fatalf("services must not import platform/deps; violations: %s", strings.Join(violations, ", "))
	}
}

func TestInterceptorsDoNotImportDepsPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)

	violations := findProductionImportSuffix(t, root, []string{"internal/interceptors"}, "/platform/deps")
	if len(violations) > 0 {
		t.Fatalf("interceptors must not import platform/deps; violations: %s", strings.Join(violations, ", "))
	}
}

func TestServicesDoNotImportWiringPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)

	violations := findProductionImportSuffix(t, root, []string{"internal/services"}, "/internal/wiring")
	if len(violations) > 0 {
		t.Fatalf("services must not import internal/wiring; violations: %s", strings.Join(violations, ", "))
	}
}

func TestInterceptorsDoNotImportWiringPackage(t *testing.T) {
	root := modroot.ModuleRoot(t)

	violations := findProductionImportSuffix(t, root, []string{"internal/interceptors"}, "/internal/wiring")
	if len(violations) > 0 {
		t.Fatalf("interceptors must not import internal/wiring; violations: %s", strings.Join(violations, ", "))
	}
}
