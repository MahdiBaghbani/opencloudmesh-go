// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigparams_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func FuzzParseSignatureInput(f *testing.F) {
	f.Add(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=1730815200;keyid="example.com#key1";alg="ed25519"`,
		"ocm",
	)
	f.Add("", "ocm")
	f.Add(`ocm=("@method");created=notanumber;keyid="x";alg="ed25519"`, "ocm")
	f.Add(`sig1=("@method");created=1;keyid="x";alg="ed25519"`, "ocm")

	f.Fuzz(func(_ *testing.T, header, label string) {
		if _, err := sigparams.ParseSignatureInput(header, label); err != nil {
			return
		}
	})
}
