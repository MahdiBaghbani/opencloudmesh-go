package keyid_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
)

func TestBuildKid(t *testing.T) {
	got := keyid.BuildKid("example.com", "key1")
	if got != "example.com#key1" {
		t.Fatalf("BuildKid = %q", got)
	}
}

func TestParseKid_HostFragment(t *testing.T) {
	parsed, err := keyid.ParseKid("example.com#key1")
	if err != nil {
		t.Fatalf("ParseKid: %v", err)
	}
	if parsed.Authority != "example.com" || parsed.Fragment != "key1" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestKidFromPublicOrigin(t *testing.T) {
	got, err := keyid.KidFromPublicOrigin("https://example.com:9200", "key1")
	if err != nil {
		t.Fatalf("KidFromPublicOrigin: %v", err)
	}
	if got != "example.com:9200#key1" {
		t.Fatalf("kid = %q", got)
	}
}

func TestKidMatches(t *testing.T) {
	if !keyid.KidMatches("example.com#key1", "example.com#key1") {
		t.Fatal("expected match")
	}
	if keyid.KidMatches("example.com#key1", "other.example#key1") {
		t.Fatal("expected mismatch")
	}
}

func TestParseKid_LegacyURI(t *testing.T) {
	parsed, err := keyid.ParseKid("https://example.com/ocm#key-1")
	if err != nil {
		t.Fatalf("ParseKid: %v", err)
	}
	if parsed.Fragment != "key-1" {
		t.Fatalf("Fragment = %q", parsed.Fragment)
	}
	if parsed.Authority != "example.com" {
		t.Fatalf("Authority = %q", parsed.Authority)
	}
}
