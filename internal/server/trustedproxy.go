// Package server provides trusted proxy utilities.
package server

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxies manages IP-based trusted proxy detection.
type TrustedProxies struct {
	networks []*net.IPNet
}

// NewTrustedProxies creates a TrustedProxies from a list of CIDR strings.
// Invalid CIDRs are silently ignored.
func NewTrustedProxies(cidrs []string) *TrustedProxies {
	tp := &TrustedProxies{}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(ip.String() + "/32")
				} else {
					_, network, _ = net.ParseCIDR(ip.String() + "/128")
				}
			}
		}
		if network != nil {
			tp.networks = append(tp.networks, network)
		}
	}
	return tp
}

// IsTrusted returns true if the IP is within any trusted proxy range.
func (tp *TrustedProxies) IsTrusted(ip net.IP) bool {
	for _, network := range tp.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP extracts the real client IP from a request.
// If the request comes from a trusted proxy, uses X-Forwarded-For.
// Otherwise uses the direct connection address.
func (tp *TrustedProxies) GetClientIP(r *http.Request) net.IP {
	// Get direct connection IP
	directIP := parseRemoteAddr(r.RemoteAddr)

	// If no trusted proxies configured or direct IP not trusted, use direct IP
	if directIP == nil || !tp.IsTrusted(directIP) {
		return directIP
	}

	// Direct IP is trusted, check X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// Also check X-Real-IP
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip
			}
		}
		return directIP
	}

	// X-Forwarded-For can contain multiple IPs, take the first one
	// Format: "client, proxy1, proxy2"
	parts := strings.Split(xff, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if ip := net.ParseIP(part); ip != nil {
			return ip
		}
	}

	return directIP
}

// parseRemoteAddr extracts the IP from net/http RemoteAddr format.
func parseRemoteAddr(addr string) net.IP {
	// RemoteAddr is typically "ip:port" or "[ip]:port" for IPv6
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe it's just an IP
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}

// GetClientIPString returns the client IP as a string for logging/rate limiting.
func (tp *TrustedProxies) GetClientIPString(r *http.Request) string {
	ip := tp.GetClientIP(r)
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}
