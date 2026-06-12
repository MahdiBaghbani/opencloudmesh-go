// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func dummyDiscClient() *discovery.Client {
	return discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode:         "off",
		MaxResponseBytes: 1 << 20,
	}, nil), nil)
}

// mockSigner adds a Signature header for tests.
type mockSigner struct {
	failSign bool
}

func (s *mockSigner) Sign(req *http.Request) error {
	if s.failSign {
		return &peercompat.ClassifiedError{
			ReasonCode: peercompat.ReasonSignatureInvalid,
			Message:    "signing failed",
		}
	}
	req.Header.Set("Signature", "mock-signature")
	return nil
}

// makePolicy builds an OutboundPolicy for tests.
func makePolicy(outboundMode string, profileRegistry *peercompat.ProfileRegistry) *outboundsigning.OutboundPolicy {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        outboundMode,
		PeerProfileOverride: "non-strict",
	}
	if profileRegistry != nil {
		contract, err := peercompat.BuildCompiledContractFromRegistry(profileRegistry)
		if err != nil {
			panic(err)
		}
		policy.PeerContract = contract
	}
	return policy
}

func newDiscoveryAwareTokenServer(tokenHandler http.HandlerFunc) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      server.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: server.URL,
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			})
			return
		}
		tokenHandler(w, r)
	}))
	return server
}
