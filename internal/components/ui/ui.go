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
	basePath  string
	templates *template.Template
}

// NewHandler creates a new UI handler.
func NewHandler(basePath string) (*Handler, error) {
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
		basePath:  basePath,
		templates: tmpl,
	}, nil
}

// TemplateData contains data passed to templates.
type TemplateData struct {
	BasePath string
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
