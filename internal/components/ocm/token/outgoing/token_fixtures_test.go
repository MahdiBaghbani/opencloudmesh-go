// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
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

func newTokenTestServer(tokenHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(tokenHandler)
}
