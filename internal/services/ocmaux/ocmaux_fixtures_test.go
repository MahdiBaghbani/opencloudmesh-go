// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

func testOCMAuxInputs() Inputs {
	rawHTTP := httpclient.New(nil, nil)
	realIP := realip.NewTrustedProxies(nil)

	return Inputs{
		DiscoveryClient: discovery.NewClient(rawHTTP, nil),
		Ratelimit: ratelimit.Inputs{
			KeyFunc: realIP.GetClientIPString,
		},
	}
}
