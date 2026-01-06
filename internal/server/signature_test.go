package server

import (
	"context"
	"testing"
)

func TestExtractHostFromKeyID(t *testing.T) {
	tests := []struct {
		keyID    string
		wantHost string
		wantErr  bool
	}{
		{
			keyID:    "https://example.com/ocm#key1",
			wantHost: "example.com",
			wantErr:  false,
		},
		{
			keyID:    "https://example.com:8443/ocm#key1",
			wantHost: "example.com:8443",
			wantErr:  false,
		},
		{
			keyID:    "http://localhost/path#keyname",
			wantHost: "localhost",
			wantErr:  false,
		},
		{
			keyID:    "https://ocm.example.org#primary-key",
			wantHost: "ocm.example.org",
			wantErr:  false,
		},
		{
			keyID:    "short",
			wantHost: "",
			wantErr:  true,
		},
		{
			keyID:    "",
			wantHost: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.keyID, func(t *testing.T) {
			host, err := ExtractHostFromKeyID(tt.keyID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for keyId %q", tt.keyID)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if host != tt.wantHost {
				t.Errorf("got host %q, want %q", host, tt.wantHost)
			}
		})
	}
}

type mockDiscoveryClient struct {
	signingCapable map[string]bool
	publicKeys     map[string]string
}

func (m *mockDiscoveryClient) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	return m.signingCapable[host], nil
}

func (m *mockDiscoveryClient) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	return m.publicKeys[keyID], nil
}

func TestPeerDiscoveryAdapter_NoClient(t *testing.T) {
	adapter := NewPeerDiscoveryAdapter(nil)

	_, err := adapter.IsSigningCapable(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error when no client configured")
	}

	_, err = adapter.GetPublicKey(context.Background(), "https://example.com#key1")
	if err == nil {
		t.Error("expected error when no client configured")
	}
}
