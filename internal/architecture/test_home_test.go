package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

// testHomeExemptions lists production files allowed to lack a co-located
// source-mapped test file ({stem}_test.go) until the listed follow-up lands.
var testHomeExemptions = map[string]string{
	"internal/components/api/auth.go": "auth behavior tested indirectly today; internal/components/api/auth_test.go missing until T8",
}

func TestTestHomeExemptionsIncludeAuth(t *testing.T) {
	reason, ok := testHomeExemptions["internal/components/api/auth.go"]
	if !ok {
		t.Fatal("internal/components/api/auth.go must remain in testHomeExemptions until T8 creates auth_test.go")
	}
	if reason == "" {
		t.Fatal("exemption reason must be documented")
	}
}

func TestExemptedProductionFilesExist(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for relPath := range testHomeExemptions {
		prodPath := filepath.Join(root, relPath)
		if _, err := os.Stat(prodPath); err != nil {
			if os.IsNotExist(err) {
				t.Fatalf("exempted production file missing: %s", relPath)
			}
			t.Fatalf("stat %s: %v", prodPath, err)
		}
	}
}

func TestExemptedFilesLackDedicatedTestHome(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for relPath := range testHomeExemptions {
		stem := strings.TrimSuffix(filepath.Base(relPath), ".go")
		testHome := filepath.Join(root, filepath.Dir(relPath), stem+"_test.go")
		if _, err := os.Stat(testHome); err == nil {
			t.Fatalf("%s has dedicated test home %s; remove exemption", relPath, filepath.Base(testHome))
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", testHome, err)
		}
	}
}
