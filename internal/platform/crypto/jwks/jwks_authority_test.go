package jwks_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestAuthorityFromBaseURL_NormalizesHostAndDefaultPort(t *testing.T) {
	scheme, authority, err := jwks.AuthorityFromBaseURL("https://Example.COM:443/ocm/path?q=1")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL: %v", err)
	}

	if scheme != "https" {
		t.Fatalf("scheme = %q, want https", scheme)
	}

	if authority != "example.com" {
		t.Fatalf("authority = %q, want example.com", authority)
	}

	scheme, authority, err = jwks.AuthorityFromBaseURL("http://Example.COM:80/")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL http: %v", err)
	}

	if scheme != "http" || authority != "example.com" {
		t.Fatalf("http default port = %s %q, want http example.com", scheme, authority)
	}
}

func TestURLForAuthority(t *testing.T) {
	got := jwks.URLForAuthority("https", "example.com")

	want := "https://example.com/.well-known/jwks.json"
	if got != want {
		t.Fatalf("URLForAuthority = %q, want %q", got, want)
	}
}
