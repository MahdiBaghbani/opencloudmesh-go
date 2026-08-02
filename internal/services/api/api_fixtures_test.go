// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func testLocalIdentity() localidentity.Identity {
	id, err := localidentity.Derive("https://localhost", "")
	if err != nil {
		panic("testLocalIdentity: " + err.Error())
	}

	return id
}

func testAPIInputs(t *testing.T) Inputs {
	t.Helper()

	cfg := config.DevConfig()
	rawHTTP := httpclient.New(nil, nil)
	realIP := realip.NewTrustedProxies(nil)

	return Inputs{
		PartyRepo:          identity.NewMemoryPartyRepo(),
		SessionRepo:        identity.NewMemorySessionRepo(),
		UserAuth:           identity.NewUserAuthFast(),
		IncomingShareRepo:  tsrepos.OpenMemory(t).IncomingShares,
		OutgoingShareRepo:  tsrepos.OpenMemory(t).OutgoingShares,
		IncomingInviteRepo: tsrepos.OpenMemory(t).IncomingInvites,
		OutgoingInviteRepo: tsrepos.OpenMemory(t).OutgoingInvites,
		HTTPClient:         httpclient.NewContextClient(rawHTTP),
		DiscoveryClient:    discovery.NewClient(rawHTTP, nil),
		LocalIdentity:      testLocalIdentity(),
		Ratelimit: ratelimit.Inputs{
			KeyFunc: realIP.GetClientIPString,
		},
		InterceptorProfiles: cfg.HTTP.Interceptors,
	}
}
