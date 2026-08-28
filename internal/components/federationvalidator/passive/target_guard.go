// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

var errTargetNotPublic = errors.New("target must be a public address")

// rejectNonPublicTarget rejects localhost literals and non-public IP literals.
// It does not resolve hostnames.
func rejectNonPublicTarget(parsed parsedTarget) error {
	scheme := ""
	if origin, err := url.Parse(parsed.origin); err == nil {
		scheme = origin.Scheme
	}

	authority, err := hostport.Normalize(parsed.targetHost, scheme)
	if err != nil {
		return errTargetNotPublic
	}

	u, err := url.Parse("dummy://" + authority)
	if err != nil {
		return errTargetNotPublic
	}

	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return errTargetNotPublic
	}

	if host == "localhost" || host == "localhost.localdomain" {
		return errTargetNotPublic
	}

	ip := net.ParseIP(host)
	if ip != nil && !isPublicIP(ip) {
		return errTargetNotPublic
	}

	return nil
}

func isPublicIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}
