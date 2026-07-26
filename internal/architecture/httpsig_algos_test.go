package architecture

import (
	"errors"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestHTTPSigAlgorithms_AsymmetricOnlyAndSHA256(t *testing.T) {
	// OCM request signatures must use asymmetric algorithms from the IANA
	// "HTTP Signature Algorithms" registry, ed25519 is RECOMMENDED, and
	// symmetric algorithms such as hmac-sha256 MUST NOT be used.
	// https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L852-L856
	// OCM content-digest values must use a hash from the IANA
	// "Hash Algorithms for HTTP Digest Fields" registry and implementations must
	// support sha-256.
	// https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L837-L840
	// This guard checks that the default allowed algorithm set satisfies those
	// invariants and that SHA-256 is the implemented digest.
	for _, alg := range sigalg.DefaultAllowed() {
		if sigalg.IsSymmetric(alg) {
			t.Errorf("DefaultAllowed algorithm %q is symmetric", alg)
		}
		if !sigalg.IsImplemented(alg) {
			t.Errorf("DefaultAllowed algorithm %q is not implemented", alg)
		}
	}
	if !slices.Contains(sigalg.DefaultAllowed(), sigalg.Ed25519) {
		t.Errorf("DefaultAllowed() = %v, want to contain %q", sigalg.DefaultAllowed(), sigalg.Ed25519)
	}
	if !sigalg.IsSymmetric("hmac-sha256") {
		t.Error(`IsSymmetric("hmac-sha256") = false, want true`)
	}
	err := sigalg.ValidateAllowed("hmac-sha256", sigalg.DefaultAllowed())
	if !errors.Is(err, sigalg.ErrSymmetricNotPermitted) {
		t.Fatalf("ValidateAllowed(\"hmac-sha256\", DefaultAllowed()) = %v, want ErrSymmetricNotPermitted", err)
	}
	digest := sigalg.SumSHA256([]byte("ocm"))
	if len(digest) != 32 {
		t.Errorf("SumSHA256 len = %d, want 32", len(digest))
	}
}
