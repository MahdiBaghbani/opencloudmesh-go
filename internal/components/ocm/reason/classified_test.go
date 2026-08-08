// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reason

import (
	"errors"
	"fmt"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestClassifyError_SignatureBodiesAndKeyLookup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("jwks lookup for %q: %w", "peer#key1", jwks.ErrKeyNotFound), ReasonKeyNotFound},
		{fmt.Errorf("resolve: %w", sigalg.ErrAlgorithmNotAllowed), ReasonSignatureInvalid},
		{fmt.Errorf("verify: %w", sigalg.ErrVerifyFailed), ReasonSignatureInvalid},
		{fmt.Errorf("sym: %w", sigalg.ErrSymmetricNotPermitted), ReasonSignatureInvalid},
		{fmt.Errorf("mismatch: %w", sigalg.ErrAlgorithmMismatch), ReasonSignatureInvalid},
		{errors.New("signature verification failed"), ReasonSignatureInvalid},
		{errors.New("content digest mismatch"), ReasonDigestMismatch},
		{errors.New("digest mismatch"), ReasonDigestMismatch},
		{errors.New(`missing required signature component "content-digest"`), ReasonUnknown},
		{errors.New("cache key not found"), ReasonUnknown},
		{NewClassifiedError(ReasonNetworkError, "wrapped", errors.New("signature key not found")), ReasonNetworkError},
	}
	for _, tc := range cases {
		got := ClassifyError(tc.err)
		if got != tc.want {
			t.Fatalf("ClassifyError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
