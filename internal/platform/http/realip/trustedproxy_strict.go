// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import (
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

func strictForwardedHeaderValue(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", ErrMissingForwardedHeader
	}

	if len(values) > 1 {
		return "", ErrConflictingForwardedHeader
	}

	return values[0], nil
}

func parseXForwardedForIPList(raw string) ([]net.IP, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrMissingForwardedHeader
	}

	parts := strings.Split(raw, ",")
	ips := make([]net.IP, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, ErrMalformedForwardedHeader
		}

		ip := net.ParseIP(part)
		if ip == nil {
			return nil, ErrMalformedForwardedHeader
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

func (tp *TrustedProxies) clientIPFromStrictXForwardedFor(raw string) (net.IP, error) {
	ips, err := parseXForwardedForIPList(raw)
	if err != nil {
		return nil, err
	}

	for i := range slices.Backward(ips) {
		if !tp.IsTrusted(ips[i]) {
			return ips[i], nil
		}
	}

	return nil, ErrMalformedForwardedHeader
}

func parseStrictXForwardedProto(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrMissingForwardedHeader
	}

	if strings.Contains(raw, ",") {
		return "", ErrConflictingForwardedHeader
	}

	proto := strings.ToLower(raw)
	if proto != schemeHTTP && proto != schemeHTTPS {
		return "", ErrMalformedForwardedHeader
	}

	return proto, nil
}

func parseStrictXForwardedHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrMissingForwardedHeader
	}

	if strings.Contains(raw, ",") {
		return "", ErrConflictingForwardedHeader
	}

	if strings.ContainsAny(raw, " \t\r\n/\\?#@") {
		return "", ErrMalformedForwardedHeader
	}

	if strings.HasPrefix(raw, "[") {
		return parseStrictBracketedForwardedHost(raw)
	}

	if h, p, err := net.SplitHostPort(raw); err == nil {
		return validateForwardedHostWithPort(h, p, raw)
	}

	if strings.Contains(raw, ":") {
		return "", ErrMalformedForwardedHeader
	}

	if !isValidForwardedHostname(raw) {
		return "", ErrMalformedForwardedHeader
	}

	return raw, nil
}

func parseStrictBracketedForwardedHost(host string) (string, error) {
	closed := strings.Index(host, "]")
	if closed <= 0 {
		return "", ErrMalformedForwardedHeader
	}

	ip := net.ParseIP(host[1:closed])
	if ip == nil || ip.To4() != nil {
		return "", ErrMalformedForwardedHeader
	}

	rest := host[closed+1:]
	if rest == "" {
		return host, nil
	}

	if !strings.HasPrefix(rest, ":") {
		return "", ErrMalformedForwardedHeader
	}

	if !isValidTCPPort(rest[1:]) {
		return "", ErrMalformedForwardedHeader
	}

	return host, nil
}

func validateForwardedHostWithPort(hostname, port, raw string) (string, error) {
	if !isValidForwardedHostname(hostname) {
		return "", ErrMalformedForwardedHeader
	}

	if !isValidTCPPort(port) {
		return "", ErrMalformedForwardedHeader
	}

	return raw, nil
}

func isValidForwardedHostname(hostname string) bool {
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n/\\?#@") {
		return false
	}

	for _, label := range strings.Split(hostname, ".") {
		if !isValidForwardedHostLabel(label) {
			return false
		}
	}

	return true
}

func isValidForwardedHostLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}

	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}

	return true
}

func isValidTCPPort(port string) bool {
	if port == "" {
		return false
	}

	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}

	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= 65535
}
