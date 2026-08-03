// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

import (
	"encoding/json"
	"testing"
)

func FuzzUnmarshalNewShareRequest(f *testing.F) {
	f.Add([]byte(`{"shareWith":"user@cloud.example","name":"doc","providerId":"p1","owner":"o@cloud.example","sender":"s@cloud.example","shareType":"user","resourceType":"file","protocol":{"name":"webdav","webdav":{"uri":"https://cloud.example/remote.php/dav/files/u/doc","permissions":["read"]}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"protocol":{"name":"multi","webdav":{"uri":"u","sharedSecret":"s","permissions":["read"]},"futureArm":{}}`))
	f.Add([]byte(`{"shareType":123,"resourceType":true}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		var req NewShareRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
	})
}
