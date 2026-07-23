package spec_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
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
