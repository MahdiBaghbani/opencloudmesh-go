// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestTLSManager_TerminatedModeSkipsCertificates(t *testing.T) {
	t.Parallel()

	mgr := tlspkg.NewTLSManager(&config.TLSConfig{Mode: config.TLSModeTerminated}, nil)

	tlsConfig, err := mgr.GetTLSConfig("example.com")
	if err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}

	if tlsConfig != nil {
		t.Fatal("expected nil TLS config for terminated mode")
	}
}

func TestServerStart_TerminatedBindsPlainHTTP(t *testing.T) {
	t.Parallel()

	port := getFreePort(t)
	cfg := config.DevConfig()
	cfg.TLS.Mode = config.TLSModeTerminated
	cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tp, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies)
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	deps := testServerDeps(t, cfg, logger)
	deps.RealIP = tp.EnableStrictForwarded()

	srv, err := New(cfg, logger, nil, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	startErr := make(chan error, 1)
	go func() {
		startErr <- srv.Start()
	}()

	addr := cfg.ListenAddr

	deadline := time.Now().Add(tshttp.DefaultShutdownWait)
	for time.Now().Before(deadline) {
		conn, dialErr := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
		if dialErr == nil {
			tshttp.MustClose(t, conn)

			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get("http://" + addr + "/api/healthz") //nolint:noctx,bodyclose // bounded test client; body closed via tshttp.MustClose below
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}

	tshttp.MustClose(t, resp.Body)

	if resp.TLS != nil {
		t.Fatal("expected plain HTTP response without TLS state")
	}

	shutdownAndDrainStart(t, srv, startErr)
}
