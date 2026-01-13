package token

import (
	"testing"
)

func TestTokenExchangeSettings_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		settings TokenExchangeSettings
		wantPath string
	}{
		{
			name:     "empty path gets default",
			settings: TokenExchangeSettings{},
			wantPath: "token",
		},
		{
			name:     "explicit path preserved",
			settings: TokenExchangeSettings{Path: "custom"},
			wantPath: "custom",
		},
		{
			name:     "nested path preserved",
			settings: TokenExchangeSettings{Path: "token/v2"},
			wantPath: "token/v2",
		},
		{
			name:     "enabled state preserved",
			settings: TokenExchangeSettings{Enabled: true},
			wantPath: "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.settings.ApplyDefaults()
			if tt.settings.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", tt.settings.Path, tt.wantPath)
			}
		})
	}
}

func TestTokenExchangeSettings_Validate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple path",
			path:    "token",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "token/v2",
			wantErr: false,
		},
		{
			name:    "valid deep nested path",
			path:    "api/v1/token",
			wantErr: false,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
			errMsg:  "must not be empty",
		},
		{
			name:    "whitespace only path",
			path:    "   ",
			wantErr: true,
			errMsg:  "must not be empty",
		},
		{
			name:    "path with ..",
			path:    "../token",
			wantErr: true,
			errMsg:  "must not contain '..'",
		},
		{
			name:    "path with .. in middle",
			path:    "foo/../bar",
			wantErr: true,
			errMsg:  "must not contain '..'",
		},
		{
			name:    "leading slash",
			path:    "/token",
			wantErr: true,
			errMsg:  "must be relative",
		},
		{
			name:    "http scheme",
			path:    "http://example.com/token",
			wantErr: true,
			errMsg:  "must not contain a scheme",
		},
		{
			name:    "https scheme",
			path:    "https://example.com/token",
			wantErr: true,
			errMsg:  "must not contain a scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &TokenExchangeSettings{Path: tt.path}
			err := s.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() error = nil, want error containing %q", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}
		})
	}
}

func TestTokenExchangeSettings_FullEndpoint(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		externalOrigin   string
		externalBasePath string
		want             string
	}{
		{
			name:             "simple path no base path",
			path:             "token",
			externalOrigin:   "https://ocm.example.com",
			externalBasePath: "",
			want:             "https://ocm.example.com/ocm/token",
		},
		{
			name:             "simple path with base path",
			path:             "token",
			externalOrigin:   "https://example.com",
			externalBasePath: "/api/v1",
			want:             "https://example.com/api/v1/ocm/token",
		},
		{
			name:             "nested path",
			path:             "token/v2",
			externalOrigin:   "https://ocm.example.com",
			externalBasePath: "",
			want:             "https://ocm.example.com/ocm/token/v2",
		},
		{
			name:             "nested path with base path",
			path:             "exchange/token",
			externalOrigin:   "https://example.com",
			externalBasePath: "/services",
			want:             "https://example.com/services/ocm/exchange/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &TokenExchangeSettings{Path: tt.path}
			got := s.FullEndpoint(tt.externalOrigin, tt.externalBasePath)
			if got != tt.want {
				t.Errorf("FullEndpoint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenExchangeSettings_RoutePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple path",
			path: "token",
			want: "/token",
		},
		{
			name: "nested path",
			path: "token/v2",
			want: "/token/v2",
		},
		{
			name: "deep nested path",
			path: "api/v1/token",
			want: "/api/v1/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &TokenExchangeSettings{Path: tt.path}
			got := s.RoutePath()
			if got != tt.want {
				t.Errorf("RoutePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// containsString checks if s contains substr.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
