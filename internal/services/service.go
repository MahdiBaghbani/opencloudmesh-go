package services

import (
	"log/slog"
	"net/http"
)

// Service represents an HTTP service that can be registered and mounted.
// This interface matches Reva's pkg/rhttp/global.Service.
type Service interface {
	Handler() http.Handler
	Prefix() string
	Close() error
	Unprotected() []string
}

// NewService is the constructor function type for services.
// Reva-shaped, but uses slog to avoid mixing log frameworks in this repo.
type NewService func(conf map[string]any, log *slog.Logger) (Service, error)
