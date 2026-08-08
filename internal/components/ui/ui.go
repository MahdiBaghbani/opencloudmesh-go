// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package ui provides the web UI (login, inbox, outgoing, wayf, accept-invite).
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler serves UI pages (login, inbox, outgoing, wayf, accept-invite).
type Handler struct {
	basePath       string
	providerDomain string // published provider domain for WAYF invite links
	templates      *template.Template
}

// NewHandler builds a UI handler. basePath and providerDomain come from the
// validated local identity contract; basePath is already normalized.
func NewHandler(basePath string, providerDomain string) (*Handler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse ui templates: %w", err)
	}

	return &Handler{
		basePath:       basePath,
		providerDomain: providerDomain,
		templates:      tmpl,
	}, nil
}

// TemplateData is passed to templates.
type TemplateData struct {
	BasePath       string
	Token          string
	ProviderDomain string
}

// Login serves the login page.
func (h *Handler) Login(w http.ResponseWriter, _ *http.Request) {
	data := TemplateData{BasePath: h.basePath}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Inbox serves the inbox page.
func (h *Handler) Inbox(w http.ResponseWriter, _ *http.Request) {
	data := TemplateData{BasePath: h.basePath}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, "inbox.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Outgoing serves the outgoing shares and invites page.
func (h *Handler) Outgoing(w http.ResponseWriter, _ *http.Request) {
	data := TemplateData{BasePath: h.basePath}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, "outgoing.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Wayf serves the WAYF provider selection page (pick federation provider for invite).
func (h *Handler) Wayf(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{
		BasePath:       h.basePath,
		Token:          r.URL.Query().Get("token"),
		ProviderDomain: h.providerDomain,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, "wayf.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// AcceptInvite serves the invite acceptance page (session-gated).
func (h *Handler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{
		BasePath:       h.basePath,
		Token:          r.URL.Query().Get("token"),
		ProviderDomain: r.URL.Query().Get("providerDomain"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := h.templates.ExecuteTemplate(w, "accept-invite.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
