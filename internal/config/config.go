// Package config provides configuration loading and validation.
package config

// Config holds the server configuration.
type Config struct {
	// ExternalOrigin is the public origin (scheme + host + port) for this instance.
	// Example: "https://localhost:9200"
	ExternalOrigin string `json:"external_origin"`

	// ExternalBasePath is the optional path prefix for app endpoints.
	// Root-only endpoints (/.well-known/ocm, /ocm-provider) are never under this path.
	// Example: "/ocm" or empty string
	ExternalBasePath string `json:"external_base_path"`

	// ListenAddr is the address to listen on.
	// Example: ":9200"
	ListenAddr string `json:"listen_addr"`

	// TLS configuration (expanded in Phase 0d)
	TLS TLSConfig `json:"tls"`

	// OutboundHTTP configuration (expanded in Phase 0d)
	OutboundHTTP OutboundHTTPConfig `json:"outbound_http"`
}

// TLSConfig holds TLS-related settings.
type TLSConfig struct {
	// Mode is one of: off, static, selfsigned, acme
	Mode string `json:"mode"`

	// CertFile and KeyFile for static mode
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`

	// HTTPPort for HTTP listener (used for ACME challenges and redirects)
	HTTPPort int `json:"http_port"`

	// HTTPSPort for HTTPS listener
	HTTPSPort int `json:"https_port"`
}

// OutboundHTTPConfig holds settings for outbound HTTP requests.
type OutboundHTTPConfig struct {
	// SSRFMode is one of: strict, off
	SSRFMode string `json:"ssrf_mode"`

	// TimeoutMS is the overall request timeout in milliseconds
	TimeoutMS int `json:"timeout_ms"`

	// ConnectTimeoutMS is the connection timeout in milliseconds
	ConnectTimeoutMS int `json:"connect_timeout_ms"`

	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects int `json:"max_redirects"`

	// MaxResponseBytes is the maximum response body size
	MaxResponseBytes int64 `json:"max_response_bytes"`

	// InsecureSkipVerify disables TLS verification (dev-only)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// DefaultConfig returns a Config with sensible defaults for local development.
func DefaultConfig() *Config {
	return &Config{
		ExternalOrigin:   "https://localhost:9200",
		ExternalBasePath: "",
		ListenAddr:       ":9200",
		TLS: TLSConfig{
			Mode:      "selfsigned",
			HTTPPort:  9280,
			HTTPSPort: 9200,
		},
		OutboundHTTP: OutboundHTTPConfig{
			SSRFMode:           "off", // off for local dev
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       3,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: true, // for local dev with self-signed certs
		},
	}
}
