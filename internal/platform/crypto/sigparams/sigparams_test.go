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
	if !strings.Contains(err.Error(), "Signature-Input") {
		t.Fatalf("error = %v, want Signature-Input in message", err)
	}
}

func TestParseSignature_RejectsMissingLabel(t *testing.T) {
	_, err := sigparams.ParseSignature(`sig1=:YWJj:`, "ocm")
	if err == nil {
		t.Fatal("expected error for missing ocm label")
	}
	if !strings.Contains(err.Error(), "Signature header") {
		t.Fatalf("error = %v, want Signature header in message", err)
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
	if !strings.Contains(raw, `alg="ed25519"`) {
		t.Fatalf("formatted missing alg: %q", raw)
	}

	params, err := sigparams.ParseSignatureInput(raw, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if params.Created != 42 {
		t.Errorf("Created = %d", params.Created)
	}
}

func TestFormatSignatureInput_OmitsEmptyAlg(t *testing.T) {
	raw := sigparams.FormatSignatureInput("ocm", []string{"@method"}, 1, "example.com#k1", "")
	if strings.Contains(raw, "alg=") {
		t.Fatalf("empty algorithm must omit alg=: %q", raw)
	}
	params, err := sigparams.ParseSignatureInput(raw, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if params.Algorithm != "" {
		t.Fatalf("Algorithm = %q, want empty", params.Algorithm)
	}
}

func TestDictionaryMember_BoundaryAware(t *testing.T) {
	// Substring "ocm=" appears inside keyid value; must not count or extract that.
	header := `sig1=("@method");created=1;keyid="https://evil.example/ocm=spoof", ocm=("@method" "@target-uri");created=2;keyid="example.com#key1";alg="ed25519"`
	if got := sigparams.CountDictionaryMembers(header, "ocm"); got != 1 {
		t.Fatalf("CountDictionaryMembers = %d, want 1", got)
	}
	entry, err := sigparams.ExtractDictionaryMember(header, "ocm")
	if err != nil {
		t.Fatalf("ExtractDictionaryMember: %v", err)
	}
	if !strings.HasPrefix(entry, `("@method" "@target-uri")`) {
		t.Fatalf("extracted wrong member: %q", entry)
	}
	params, err := sigparams.ParseSignatureInput(header, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if params.Created != 2 || params.KeyID != "example.com#key1" {
		t.Fatalf("params = %+v", params)
	}
}

func TestDictionaryMember_QuotedCommaSpoof(t *testing.T) {
	// Comma + "ocm=" inside a quoted keyid must not invent a second member.
	header := `sig1=("@method");created=1;keyid="x, ocm=spoof", ocm=("@method" "@target-uri");created=2;keyid="example.com#key1";alg="ed25519"`
	if got := sigparams.CountDictionaryMembers(header, "ocm"); got != 1 {
		t.Fatalf("CountDictionaryMembers = %d, want 1", got)
	}
	params, err := sigparams.ParseSignatureInput(header, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}
	if params.Created != 2 || params.KeyID != "example.com#key1" {
		t.Fatalf("params = %+v", params)
	}

	spoofOnly := `sig1=("@method");created=1;keyid="x, ocm=("@method")"`
	if got := sigparams.CountDictionaryMembers(spoofOnly, "ocm"); got != 0 {
		t.Fatalf("spoof-only CountDictionaryMembers = %d, want 0", got)
	}
	if _, err := sigparams.ParseSignatureInput(spoofOnly, "ocm"); err == nil {
		t.Fatal("expected missing ocm label when only quoted spoof exists")
	}
}

func TestCountDictionaryMembers_DuplicateLabel(t *testing.T) {
	header := `ocm=("@method");created=1;keyid="a#1", ocm=("@method");created=2;keyid="b#1"`
	if got := sigparams.CountDictionaryMembers(header, "ocm"); got != 2 {
		t.Fatalf("CountDictionaryMembers = %d, want 2", got)
	}
}
