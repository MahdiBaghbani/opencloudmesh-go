package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestSignatureLabelOCM(t *testing.T) {
	if spec.SignatureLabelOCM != "ocm" {
		t.Fatalf("SignatureLabelOCM = %q, want %q", spec.SignatureLabelOCM, "ocm")
	}
	if spec.SignatureLabelOCM != sigparams.SignatureLabelOCM {
		t.Fatalf("SignatureLabelOCM = %q, want sigparams alias %q",
			spec.SignatureLabelOCM, sigparams.SignatureLabelOCM)
	}
}

// signatureClosedPathFiles are production files on the closed migration path.
// Each must not contain raw signature-label wire string literals; use spec.*.
var signatureClosedPathFiles = []string{
	"internal/components/ocm/policy/compiler.go",
}

func TestSignatureClosedPathNoRawWireLiterals(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for _, rel := range signatureClosedPathFiles {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if strings.Contains(string(data), `"ocm"`) {
				t.Errorf("%s still contains raw signature label literal \"ocm\"; use spec.*", rel)
			}
		})
	}
}
