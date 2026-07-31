// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// mockSigner adds a Signature header for tests.
type mockSigner struct {
	failSign bool
}

func (s *mockSigner) Sign(req *http.Request) error {
	if s.failSign {
		return &reason.ClassifiedError{
			ReasonCode: reason.ReasonSignatureInvalid,
			Message:    "signing failed",
		}
	}

	req.Header.Set("Signature", "mock-signature")

	return nil
}

// httpSigDiscovery returns a discovery document that advertises the http-sig
// capability.
func httpSigDiscovery() *spec.Discovery {
	return &spec.Discovery{
		Capabilities: []string{spec.CapabilityHTTPSig},
	}
}

// noHTTPSigDiscovery returns a discovery document that does not advertise
// http-sig.
func noHTTPSigDiscovery() *spec.Discovery {
	return &spec.Discovery{}
}

func newTokenTestServer(tokenHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(tokenHandler)
}
