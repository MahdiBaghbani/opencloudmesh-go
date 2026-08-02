// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"testing"
)

// StrictProtocolPair manages two strict-mode subprocess servers configured for
// protocol integration tests: static TLS, SSRF strict with loopback route
// policy, and JSON persistence.
type StrictProtocolPair struct {
	BinaryPath string
	Server1    *SubprocessServer
	Server2    *SubprocessServer
}

// StrictProtocolPairExtraConfigBuilder builds the strict protocol TOML overlay
// after listener ports and SSRF allowlist ports are known.
type StrictProtocolPairExtraConfigBuilder func(allowedPorts []int, moduleRoot, loopbackHost string) string

// StrictProtocolPairStartOptions configures strict protocol pair subprocess startup.
type StrictProtocolPairStartOptions struct {
	ExtraConfigBuilder StrictProtocolPairExtraConfigBuilder
	TLSRootCAFile      string
	ExtraFiles         map[string]string
	ExtraAllowedPorts  []int
}

// StartStrictProtocolPairWithOptions starts two strict subprocess servers using
// caller-supplied TOML overlays and TLS trust material.
func StartStrictProtocolPairWithOptions(t *testing.T, opts StrictProtocolPairStartOptions) *StrictProtocolPair {
	t.Helper()

	if opts.ExtraConfigBuilder == nil {
		t.Fatal("strict protocol pair requires ExtraConfigBuilder")
	}

	if opts.TLSRootCAFile == "" {
		t.Fatal("strict protocol pair requires TLSRootCAFile")
	}

	loopbackHost := ResolveLoopbackHostname(t)

	port1, err := getFreePort(t.Context())
	if err != nil {
		t.Fatalf("reserve port for strict-pair-1: %v", err)
	}

	port2, err := getFreePort(t.Context())
	if err != nil {
		t.Fatalf("reserve port for strict-pair-2: %v", err)
	}

	allowedPorts := make([]int, 0, 2+len(opts.ExtraAllowedPorts))
	allowedPorts = append(allowedPorts, port1, port2)
	allowedPorts = append(allowedPorts, opts.ExtraAllowedPorts...)

	binaryPath := BuildBinary(t)
	moduleRoot := FindProjectRoot(t)
	extra := opts.ExtraConfigBuilder(allowedPorts, moduleRoot, loopbackHost)

	base := SubprocessConfig{
		Mode:                   "strict",
		DisableUseEnvFallback:  true,
		TLSRootCAFile:          opts.TLSRootCAFile,
		BootstrapAdminPassword: "testpassword123",
		ExtraConfig:            extra,
		ExtraFiles:             opts.ExtraFiles,
	}

	cfg1 := base
	cfg1.Name = "strict-pair-1"
	cfg1.Port = port1

	cfg2 := base
	cfg2.Name = "strict-pair-2"
	cfg2.Port = port2

	server1 := StartSubprocessServer(t, binaryPath, cfg1)
	server2 := StartSubprocessServer(t, binaryPath, cfg2)

	return &StrictProtocolPair{
		BinaryPath: binaryPath,
		Server1:    server1,
		Server2:    server2,
	}
}

// Stop stops both subprocess servers.
func (p *StrictProtocolPair) Stop(t *testing.T) {
	t.Helper()

	if p.Server1 != nil {
		p.Server1.Stop(t)
	}

	if p.Server2 != nil {
		p.Server2.Stop(t)
	}
}

// DumpLogs outputs logs from both subprocess servers.
func (p *StrictProtocolPair) DumpLogs(t *testing.T) {
	t.Helper()

	if p.Server1 != nil {
		p.Server1.DumpLogs(t)
	}

	if p.Server2 != nil {
		p.Server2.DumpLogs(t)
	}
}
