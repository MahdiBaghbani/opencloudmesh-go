package service

import (
	"log/slog"
	"net/http"
)

// Service represents an HTTP service that can be registered and mounted.
type Service interface {
	Handler() http.Handler
	Prefix() string
	Close() error
	Unprotected() []string
}

// NewService is the constructor function type for services.
type NewService func(conf map[string]any, log *slog.Logger) (Service, error)
