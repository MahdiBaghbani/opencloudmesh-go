package service

import (
	"net/http"
)

// Service represents an HTTP service constructed via the static wiring table and mounted on the host router.
type Service interface {
	Handler() http.Handler
	Prefix() string
	Close() error
}
