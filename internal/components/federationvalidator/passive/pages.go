// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import "net/http"

type startPageData struct {
	FormAction string
}

// HandleStartPage serves GET /start.
func (h *Handler) HandleStartPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	data := startPageData{
		FormAction: joinReportPath(h.externalBasePath, manifestServicePrefix, RouteStartCreateSession),
	}

	h.writeHTMLTemplate(w, "start.html", http.StatusOK, data)
}
