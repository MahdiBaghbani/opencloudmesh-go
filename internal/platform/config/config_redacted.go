// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"strings"
)

// Redacted returns a string representation of the config with secrets redacted.
func (c *Config) Redacted() string {
	var sb strings.Builder
	redactedWriteString(&sb, "Config{\n")
	redactedFprintf(&sb, "  Mode: %q,\n", c.Mode)
	redactedFprintf(&sb, "  PublicOrigin: %q,\n", c.PublicOrigin)
	redactedFprintf(&sb, "  ExternalBasePath: %q,\n", c.ExternalBasePath)
	redactedFprintf(&sb, "  ListenAddr: %q,\n", c.ListenAddr)
	redactedWriteString(&sb, "  Server: {\n")
	redactedFprintf(&sb, "    TrustedProxies: %v,\n", c.Server.TrustedProxies)
	redactedWriteString(&sb, "    BootstrapAdmin: {\n")
	redactedFprintf(&sb, "      Username: %q,\n", c.Server.BootstrapAdmin.Username)
	redactedWriteString(&sb, "      Password: [REDACTED],\n")
	redactedFprintf(&sb, "      CredentialFile: %q,\n", c.Server.BootstrapAdmin.CredentialFile)
	redactedWriteString(&sb, "    },\n")
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  TLS: {\n")
	redactedFprintf(&sb, "    Mode: %q,\n", c.TLS.Mode)
	redactedFprintf(&sb, "    CertFile: %q,\n", c.TLS.CertFile)
	redactedFprintf(&sb, "    KeyFile: %q,\n", c.TLS.KeyFile)
	redactedFprintf(&sb, "    HTTPPort: %d,\n", c.TLS.HTTPPort)
	redactedFprintf(&sb, "    HTTPSPort: %d,\n", c.TLS.HTTPSPort)
	redactedFprintf(&sb, "    SelfSignedDir: %q,\n", c.TLS.SelfSignedDir)
	redactedFprintf(&sb, "    TLSDir: %q,\n", c.TLS.TLSDir)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  OutboundHTTP: {\n")
	redactedWriteString(&sb, "    SSRF: {\n")
	redactedFprintf(&sb, "      Mode: %q,\n", c.OutboundHTTP.SSRF.Mode)

	if c.OutboundHTTP.SSRF.RoutePolicy != "" {
		redactedFprintf(&sb, "      RoutePolicy: %q,\n", c.OutboundHTTP.SSRF.RoutePolicy)
	}

	redactedFprintf(&sb, "      RoutePoliciesCount: %d,\n", len(c.OutboundHTTP.SSRF.RoutePolicies))
	redactedWriteString(&sb, "    },\n")
	redactedFprintf(&sb, "    TLSRootCAFile: %q,\n", c.OutboundHTTP.TLSRootCAFile)
	redactedFprintf(&sb, "    TLSRootCADir: %q,\n", c.OutboundHTTP.TLSRootCADir)
	redactedFprintf(&sb, "    TimeoutMS: %d,\n", c.OutboundHTTP.TimeoutMS)
	redactedFprintf(&sb, "    MaxRedirects: %d,\n", c.OutboundHTTP.MaxRedirects)
	redactedFprintf(&sb, "    MaxResponseBytes: %d,\n", c.OutboundHTTP.MaxResponseBytes)
	redactedFprintf(&sb, "    InsecureSkipVerify: %v,\n", c.OutboundHTTP.InsecureSkipVerify)
	redactedFprintf(&sb, "    ProxyURL: %q,\n", c.OutboundHTTP.ProxyURL)
	redactedFprintf(&sb, "    UseEnvFallback: %v,\n", c.OutboundHTTP.UseEnvFallback)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  Signature: {\n")
	redactedFprintf(&sb, "    KeyPath: %q,\n", c.Signature.KeyPath)
	redactedFprintf(&sb, "    Label: %q,\n", c.Signature.Label)
	redactedFprintf(&sb, "    KidFragment: %q,\n", c.Signature.KidFragment)
	redactedFprintf(&sb, "    CreatedMaxAgeSeconds: %d,\n", c.Signature.CreatedMaxAgeSeconds)
	redactedFprintf(&sb, "    CreatedMaxSkewSeconds: %d,\n", c.Signature.CreatedMaxSkewSeconds)
	redactedFprintf(&sb, "    AllowedAlgorithms: %v,\n", c.Signature.AllowedAlgorithms)
	redactedFprintf(&sb, "    JwksURI: %q,\n", c.Signature.JwksURI)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  Logging: {\n")
	redactedFprintf(&sb, "    Level: %q,\n", c.Logging.Level)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  TokenExchange: {\n")
	redactedFprintf(&sb, "    Path: %q,\n", c.TokenExchange.Path)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  HTTP: {\n")
	redactedFprintf(&sb, "    ServicesCount: %d,\n", len(c.HTTP.Services))

	if len(c.HTTP.Services) > 0 {
		redactedWriteString(&sb, "    Services: [")

		first := true
		for name := range c.HTTP.Services {
			if !first {
				redactedWriteString(&sb, ", ")
			}

			redactedFprintf(&sb, "%q", name)

			first = false
		}

		redactedWriteString(&sb, "],\n")
	}

	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  PeerTrust: {\n")
	redactedFprintf(&sb, "    Enabled: %v,\n", c.PeerTrust.Enabled)
	redactedFprintf(&sb, "    ConfigPathsCount: %d,\n", len(c.PeerTrust.ConfigPaths))
	redactedFprintf(&sb, "    Policy.AllowListCount: %d,\n", len(c.PeerTrust.Policy.AllowList))
	redactedFprintf(&sb, "    Policy.DenyListCount: %d,\n", len(c.PeerTrust.Policy.DenyList))
	redactedFprintf(&sb, "    MembershipCache.TTLSeconds: %d,\n", c.PeerTrust.MembershipCache.TTLSeconds)
	redactedFprintf(&sb, "    MembershipCache.MaxStaleSeconds: %d,\n", c.PeerTrust.MembershipCache.MaxStaleSeconds)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "  Persistence: {\n")
	redactedFprintf(&sb, "    Backend: %q,\n", c.Persistence.Backend)
	redactedFprintf(&sb, "    DataDir: %q,\n", c.Persistence.DataDir)
	redactedWriteString(&sb, "  },\n")
	redactedWriteString(&sb, "}")

	return sb.String()
}

func redactedWriteString(sb *strings.Builder, s string) {
	//nolint:errcheck // strings.Builder writes cannot fail
	sb.WriteString(s)
}

func redactedFprintf(sb *strings.Builder, format string, args ...any) {
	//nolint:errcheck // strings.Builder writes cannot fail
	fmt.Fprintf(sb, format, args...)
}
