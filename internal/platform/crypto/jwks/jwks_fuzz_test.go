// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"encoding/json"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func FuzzUnmarshalJWKS(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"example.com#key1","use":"sig","alg":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`))
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kid":"k","n":"abc","e":"AQAB","alg":"RS256"}]}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		var set jwks.Set
		if err := json.Unmarshal(data, &set); err != nil {
			return
		}

		for _, key := range set.Keys {
			if key.Kid == "" {
				continue
			}

			if _, err := set.ResolveExactKeyID(key.Kid); err != nil {
				continue
			}
		}
	})
}
