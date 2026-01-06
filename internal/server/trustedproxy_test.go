package server

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestTrustedProxies_IsTrusted(t *testing.T) {
	tp := NewTrustedProxies([]string{"127.0.0.0/8", "::1/128", "10.0.0.0/8"})

	tests := []struct {
		ip      string
		trusted bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.255", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"::1", true},
		{"::2", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := tp.IsTrusted(ip)
			if got != tt.trusted {
				t.Errorf("IsTrusted(%s) = %v, want %v", tt.ip, got, tt.trusted)
			}
		})
	}
}

func TestTrustedProxies_GetClientIP_Direct(t *testing.T) {
	// No trusted proxies
	tp := NewTrustedProxies(nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8") // Should be ignored

	ip := tp.GetClientIP(req)
	if ip.String() != "192.168.1.100" {
		t.Errorf("got %s, want 192.168.1.100", ip)
	}
}

func TestTrustedProxies_GetClientIP_Trusted(t *testing.T) {
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1")

	ip := tp.GetClientIP(req)
	if ip.String() != "8.8.8.8" {
		t.Errorf("got %s, want 8.8.8.8", ip)
	}
}

func TestTrustedProxies_GetClientIP_XRealIP(t *testing.T) {
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	ip := tp.GetClientIP(req)
	if ip.String() != "1.2.3.4" {
		t.Errorf("got %s, want 1.2.3.4", ip)
	}
}

func TestTrustedProxies_GetClientIP_UntrustedIgnoresHeader(t *testing.T) {
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345" // Not in trusted range
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ip := tp.GetClientIP(req)
	if ip.String() != "192.168.1.100" {
		t.Errorf("got %s, want 192.168.1.100 (direct IP, not XFF)", ip)
	}
}

func TestTrustedProxies_IPv6(t *testing.T) {
	tp := NewTrustedProxies([]string{"::1/128"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:12345"
	req.Header.Set("X-Forwarded-For", "2001:db8::1")

	ip := tp.GetClientIP(req)
	if ip.String() != "2001:db8::1" {
		t.Errorf("got %s, want 2001:db8::1", ip)
	}
}

func TestParseRemoteAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			ip := parseRemoteAddr(tt.addr)
			if ip == nil {
				t.Fatalf("parseRemoteAddr returned nil for %s", tt.addr)
			}
			if ip.String() != tt.want {
				t.Errorf("got %s, want %s", ip, tt.want)
			}
		})
	}
}

func TestNewTrustedProxies_SingleIP(t *testing.T) {
	// Test that single IPs (not CIDR) work
	tp := NewTrustedProxies([]string{"192.168.1.1"})

	if !tp.IsTrusted(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be trusted")
	}
	if tp.IsTrusted(net.ParseIP("192.168.1.2")) {
		t.Error("expected 192.168.1.2 to not be trusted")
	}
}
