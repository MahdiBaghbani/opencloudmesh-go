// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

const (
	targetSchemeHTTP  = "http"
	targetSchemeHTTPS = "https"
)

var (
	errTargetRequired = errors.New("target is required")
	errTargetForm     = errors.New("target must be an OCM address or an absolute http(s) URL")
	errTargetScheme   = errors.New("target scheme must be http or https")
	errInvalidTarget  = errors.New("invalid target")
	errTargetHost     = errors.New("target must include a host")
)

// parsedTarget is the pure rewrite of operator input. remoteOCMID is set
// only for OCM-address input; URL input leaves it nil.
type parsedTarget struct {
	origin      string
	targetHost  string
	remoteOCMID *string
}

// parseTarget rewrites operator input into a normalized origin and TargetHost.
// Input that contains "://" is treated as a URL; otherwise it must be an OCM
// address. This function does not fetch discovery documents.
//
// TargetHost is the initial correlation authority (normalized URL host or
// OCM provider). Later probe or discovery may replace it only when a
// discovery endPoint supplies a different valid endpoint authority. That
// rewrite is outside parseTarget.
func parseTarget(raw string) (parsedTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return parsedTarget{}, errTargetRequired
	}

	if strings.Contains(raw, "://") {
		return parseURLTarget(raw)
	}

	return parseOCMTarget(raw)
}

func parseURLTarget(raw string) (parsedTarget, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		// url.Parse embeds the raw input, including userinfo, in its error.
		return parsedTarget{}, errInvalidTarget
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != targetSchemeHTTP && scheme != targetSchemeHTTPS {
		return parsedTarget{}, errTargetScheme
	}

	if parsed.User != nil {
		return parsedTarget{}, errInvalidTarget
	}

	if parsed.Host == "" {
		return parsedTarget{}, errTargetHost
	}

	host, err := hostport.Normalize(parsed.Host, scheme)
	if err != nil {
		return parsedTarget{}, errInvalidTarget
	}

	return parsedTarget{
		origin:     scheme + "://" + host,
		targetHost: host,
	}, nil
}

func parseOCMTarget(raw string) (parsedTarget, error) {
	if !strings.Contains(raw, "@") {
		return parsedTarget{}, errTargetForm
	}

	provider, err := address.NormalizedProviderFrom(raw, targetSchemeHTTPS)
	if err != nil {
		return parsedTarget{}, errInvalidTarget
	}

	remote := raw

	return parsedTarget{
		origin:      targetSchemeHTTPS + "://" + provider,
		targetHost:  provider,
		remoteOCMID: &remote,
	}, nil
}

// targetClientMessage returns a static client-facing parse error. It never
// interpolates operator input, host, or userinfo.
func targetClientMessage(err error) string {
	switch {
	case errors.Is(err, errTargetRequired):
		return errTargetRequired.Error()
	case errors.Is(err, errTargetForm):
		return errTargetForm.Error()
	case errors.Is(err, errTargetScheme):
		return errTargetScheme.Error()
	case errors.Is(err, errTargetHost):
		return errTargetHost.Error()
	default:
		return errInvalidTarget.Error()
	}
}
