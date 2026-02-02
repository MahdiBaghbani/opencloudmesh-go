// Package ui provides the minimal web UI for the OCM server.
package ui

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler serves the UI pages.
type Handler struct {
	basePath       string
	wayfEnabled    bool
	providerDomain string // raw host[:port] for WAYF invite links
	templates      *template.Template
}

// NewHandler creates a new UI handler.
func NewHandler(basePath string, wayfEnabled bool, providerDomain string) (*Handler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	// Normalize base path
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	basePath = strings.TrimSuffix(basePath, "/")

	return &Handler{
		basePath:       basePath,
		wayfEnabled:    wayfEnabled,
		providerDomain: providerDomain,
		templates:      tmpl,
	}, nil
}

// TemplateData contains data passed to templates.
type TemplateData struct {
	BasePath       string
	Token          string
	ProviderDomain string
}

// Login serves the login page.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{BasePath: h.basePath}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Inbox serves the inbox page.
func (h *Handler) Inbox(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{BasePath: h.basePath}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "inbox.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// Wayf serves the WAYF (Where Are You From) provider selection page.
// This is a public page that lets the user pick a federation provider
// to accept an invite from.
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

// AcceptInvite serves the invite acceptance page (session-gated by middleware).
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
