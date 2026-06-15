package sigparams_test

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestParseSignatureInput_OCM(t *testing.T) {
	header := `ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=1730815200;keyid="example.com#key1";alg="ed25519"`

	params, err := sigparams.ParseSignatureInput(header, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}

	if params.KeyID != "example.com#key1" {
		t.Errorf("KeyID = %q", params.KeyID)
	}
	if params.Algorithm != "ed25519" {
		t.Errorf("Algorithm = %q", params.Algorithm)
	}
	if params.Created != 1730815200 {
		t.Errorf("Created = %d", params.Created)
	}
	if len(params.Components) != 5 {
		t.Fatalf("Components = %v, want 5", params.Components)
	}
}

func TestParseSignatureInput_RejectsMissingLabel(t *testing.T) {
	_, err := sigparams.ParseSignatureInput(`sig1=("@method");created=1;keyid="x";alg="ed25519"`, "ocm")
	if err == nil {
		t.Fatal("expected error for missing ocm label")
	}
}

func TestParseSignature_RejectsInvalidEncoding(t *testing.T) {
	_, err := sigparams.ParseSignature(`ocm=:not-valid!!!:`, "ocm")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFormatRoundTrip(t *testing.T) {
	components := []string{"@method", "@target-uri", "date"}
	raw := sigparams.FormatSignatureInput("ocm", components, 42, "example.com#key1", "ed25519")
	if !strings.Contains(raw, "ocm=(") {
		t.Fatalf("formatted = %q", raw)
	}

	params, err := sigparams.ParseSignatureInput(raw, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if params.Created != 42 {
		t.Errorf("Created = %d", params.Created)
	}
}
