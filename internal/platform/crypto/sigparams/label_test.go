package sigparams_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestSignatureLabelOCM(t *testing.T) {
	if sigparams.SignatureLabelOCM != "ocm" {
		t.Fatalf("SignatureLabelOCM = %q, want %q", sigparams.SignatureLabelOCM, "ocm")
	}
}
