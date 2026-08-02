// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

func hasValidationError(errs []ValidationError, name string) bool {
	for _, e := range errs {
		if e.Name == name {
			return true
		}
	}

	return false
}

func validWebapp() *WebappProtocol {
	return &WebappProtocol{
		URI:          "https://sender.example/apps/files/abc",
		Targets:      []string{"blank"},
		Permissions:  []string{"view", "read"},
		Requirements: []string{RequirementMustExchangeToken},
		SharedSecret: "topsecret",
	}
}
