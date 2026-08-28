// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import (
	"errors"
	"net"
	"testing"
)

func TestNewTrustedProxiesStrict_RejectsInvalid(t *testing.T) {
	t.Parallel()

	_, err := NewTrustedProxiesStrict([]string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid trusted proxy")
	}
}

func TestNewTrustedProxiesStrict_SingleIP(t *testing.T) {
	t.Parallel()

	tp, err := NewTrustedProxiesStrict([]string{"192.168.1.1"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	if !tp.IsTrusted(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be trusted")
	}

	if tp.IsTrusted(net.ParseIP("192.168.1.2")) {
		t.Error("expected 192.168.1.2 to not be trusted")
	}
}

func TestParseStrictXForwardedHost_BracketedIPv4Rejected(t *testing.T) {
	t.Parallel()

	_, err := parseStrictXForwardedHost("[1.2.3.4]")
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestParseStrictXForwardedHost_BracketedIPv4WithPortRejected(t *testing.T) {
	t.Parallel()

	_, err := parseStrictXForwardedHost("[1.2.3.4]:443")
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestParseStrictXForwardedHost_BracketedIPv6(t *testing.T) {
	t.Parallel()

	got, err := parseStrictXForwardedHost("[2001:db8::1]")
	if err != nil {
		t.Fatalf("parseStrictXForwardedHost: %v", err)
	}

	if got != "[2001:db8::1]" {
		t.Errorf("got %q, want [2001:db8::1]", got)
	}
}

func TestParseStrictXForwardedHost_BracketedIPv6WithPort(t *testing.T) {
	t.Parallel()

	got, err := parseStrictXForwardedHost("[2001:db8::1]:8443")
	if err != nil {
		t.Fatalf("parseStrictXForwardedHost: %v", err)
	}

	if got != "[2001:db8::1]:8443" {
		t.Errorf("got %q, want [2001:db8::1]:8443", got)
	}
}

func TestParseStrictXForwardedHost_HostWithPort(t *testing.T) {
	t.Parallel()

	got, err := parseStrictXForwardedHost("cloud.example.com:443")
	if err != nil {
		t.Fatalf("parseStrictXForwardedHost: %v", err)
	}

	if got != "cloud.example.com:443" {
		t.Errorf("got %q, want cloud.example.com:443", got)
	}
}

func TestParseStrictXForwardedHost_InvalidPortRejected(t *testing.T) {
	t.Parallel()

	_, err := parseStrictXForwardedHost("cloud.example.com:0")
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestParseStrictXForwardedHost_InvalidBracketedPortRejected(t *testing.T) {
	t.Parallel()

	_, err := parseStrictXForwardedHost("[2001:db8::1]:abc")
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestParseStrictXForwardedHost_UnbracketedIPv6Rejected(t *testing.T) {
	t.Parallel()

	_, err := parseStrictXForwardedHost("2001:db8::1")
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}
