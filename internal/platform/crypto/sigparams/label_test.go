// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigparams_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func TestSignatureLabelOCM(t *testing.T) {
	if sigparams.SignatureLabelOCM != "ocm" {
		t.Fatalf("SignatureLabelOCM = %q, want %q", sigparams.SignatureLabelOCM, "ocm")
	}
}
