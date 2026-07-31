// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigparams_test

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestSignatureTagOCM(t *testing.T) {
	if sigparams.SignatureTagOCM != "ocm" {
		t.Fatalf("SignatureTagOCM = %q, want %q", sigparams.SignatureTagOCM, "ocm")
	}
}

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

func TestFormatSignatureInput_AlwaysIncludesTagOCM(t *testing.T) {
	raw := sigparams.FormatSignatureInput("ocm", []string{"@method"}, 1, "example.com#k1", "ed25519")
	if strings.Count(raw, `tag="ocm"`) != 1 {
		t.Fatalf("Signature-Input must contain exactly one tag=\"ocm\": %q", raw)
	}

	if !strings.HasSuffix(raw, `;tag="ocm"`) {
		t.Fatalf("tag=\"ocm\" must be appended at the end: %q", raw)
	}

	params, err := sigparams.ParseSignatureInput(raw, "ocm")
	if err != nil {
		t.Fatalf("ParseSignatureInput: %v", err)
	}

	if params.Created != 1 || params.KeyID != "example.com#k1" {
		t.Fatalf("params = %+v", params)
	}
}

func TestFormatSignatureInput_OmitsEmptyAlg(t *testing.T) {
	raw := sigparams.FormatSignatureInput("ocm", []string{"@method"}, 1, "example.com#k1", "")
	if strings.Contains(raw, "alg=") {
		t.Fatalf("empty algorithm must omit alg=: %q", raw)
	}

	if strings.Count(raw, `tag="ocm"`) != 1 {
		t.Fatalf("Signature-Input must still contain exactly one tag=\"ocm\" when alg is empty: %q", raw)
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

func TestParseSignatureInput_RejectsDuplicateCoveredComponents(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "duplicate derived @method",
			header: `ocm=("@method" "@method" "@target-uri");created=1;keyid="a#1";alg="ed25519"`,
		},
		{
			name:   "duplicate ordinary content-digest",
			header: `ocm=("@method" "content-digest" "content-digest");created=1;keyid="a#1";alg="ed25519"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sigparams.ParseSignatureInput(tt.header, "ocm")
			if err == nil {
				t.Fatal("expected duplicate covered component rejection")
			}

			if !strings.Contains(err.Error(), "duplicate covered component") {
				t.Fatalf("error = %v, want duplicate covered component", err)
			}
		})
	}
}

func TestValidateExactlyOneLabel(t *testing.T) {
	t.Run("single_ocm", func(t *testing.T) {
		header := `ocm=("@method");created=1;keyid="a#1"`
		if err := sigparams.ValidateExactlyOneLabel(header, "ocm"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("foreign_label", func(t *testing.T) {
		header := `sig1=("@method");created=1;keyid="a#1", ocm=("@method");created=2;keyid="b#1"`

		err := sigparams.ValidateExactlyOneLabel(header, "ocm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("duplicate_ocm", func(t *testing.T) {
		header := `ocm=("@method");created=1;keyid="a#1", ocm=("@method");created=2;keyid="b#1"`

		err := sigparams.ValidateExactlyOneLabel(header, "ocm")
		if err == nil {
			t.Fatal("expected duplicate rejection")
		}

		if !strings.Contains(err.Error(), `multiple "ocm" signatures`) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("only_foreign", func(t *testing.T) {
		header := `sig1=("@method");created=1;keyid="a#1"`

		err := sigparams.ValidateExactlyOneLabel(header, "ocm")
		if err == nil {
			t.Fatal("expected rejection when no ocm member is present")
		}

		if !strings.Contains(err.Error(), "ocm") {
			t.Fatalf("error = %v, want missing ocm member", err)
		}
	})
}

// TestValidateExactlyOneLabel_AcceptsForeignLabelsWithOneOCM pins the target
// v1.4 parser contract: a foreign dictionary label alongside exactly one ocm
// member must be accepted, since only the ocm member is meaningful.
func TestValidateExactlyOneLabel_AcceptsForeignLabelsWithOneOCM(t *testing.T) {
	header := `sig1=("@method");created=1;keyid="a#1", ocm=("@method");created=2;keyid="b#1"`
	if err := sigparams.ValidateExactlyOneLabel(header, "ocm"); err != nil {
		t.Fatalf("expected foreign labels alongside exactly one ocm member to be accepted, got: %v", err)
	}
}

func TestValidateExactlyOneLabel_RejectsDuplicateOCMAlongsideForeignLabel(t *testing.T) {
	header := `sig1=("@method");created=1;keyid="a#1", ocm=("@method");created=2;keyid="b#1", ocm=("@method");created=3;keyid="c#1"`

	err := sigparams.ValidateExactlyOneLabel(header, "ocm")
	if err == nil {
		t.Fatal("expected duplicate ocm member rejection alongside a foreign label")
	}

	if !strings.Contains(err.Error(), `multiple "ocm" signatures`) {
		t.Fatalf("error = %v, want duplicate ocm member error", err)
	}
}

func TestValidateExactlyOneLabel_RejectsMissingOCMAmongForeignLabels(t *testing.T) {
	header := `sig1=("@method");created=1;keyid="a#1", sig2=("@method");created=2;keyid="b#1"`

	err := sigparams.ValidateExactlyOneLabel(header, "ocm")
	if err == nil {
		t.Fatal("expected rejection when no ocm member is present among foreign labels")
	}

	if !strings.Contains(err.Error(), "ocm") {
		t.Fatalf("error = %v, want missing ocm member", err)
	}
}
