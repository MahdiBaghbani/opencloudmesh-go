// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigparams

import (
	"encoding/base64"
	"fmt"
)

func decodeStdBase64(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode base64: %w", err)
	}

	return raw, nil
}

func encodeStdBase64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}
