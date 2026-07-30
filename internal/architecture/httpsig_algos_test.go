package architecture

import (
	"errors"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestHTTPSigAlgorithms_AsymmetricOnlyAndSHA256(t *testing.T) {
	// OCM request signatures use an asymmetric algorithm identified by the JWK
	// `alg` parameter from the IANA JOSE registry (RFC7518); Ed25519 is
	// RECOMMENDED. The `none` algorithm and symmetric MAC algorithms such as
	// HS256 MUST NOT be used.
	// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L901
	// OCM content-digest values must use a hash from the IANA
	// "Hash Algorithms for HTTP Digest Fields" registry and implementations must
	// support sha-256.
	// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L856-L860
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
