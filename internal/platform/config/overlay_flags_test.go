// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import "testing"

func TestOverlayNetFlags(t *testing.T) {
	cfg := StrictConfig()
	listen := ":9443"
	origin := "https://peer.example"
	basePath := "/ocm"

	overlayNetFlags(cfg, FlagOverrides{
		ListenAddr:       &listen,
		PublicOrigin:     &origin,
		ExternalBasePath: &basePath,
	})

	if cfg.ListenAddr != listen {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, listen)
	}

	if cfg.PublicOrigin != origin {
		t.Errorf("PublicOrigin = %q, want %q", cfg.PublicOrigin, origin)
	}

	if cfg.ExternalBasePath != basePath {
		t.Errorf("ExternalBasePath = %q, want %q", cfg.ExternalBasePath, basePath)
	}
}

func TestOverlayNetFlags_SkipsNilAndEmpty(t *testing.T) {
	cfg := StrictConfig()
	beforeListen := cfg.ListenAddr
	beforeOrigin := cfg.PublicOrigin
	beforeBasePath := cfg.ExternalBasePath
	empty := ""

	overlayNetFlags(cfg, FlagOverrides{
		ListenAddr:       &empty,
		PublicOrigin:     nil,
		ExternalBasePath: &empty,
	})

	if cfg.ListenAddr != beforeListen {
		t.Errorf("ListenAddr = %q, want unchanged %q", cfg.ListenAddr, beforeListen)
	}

	if cfg.PublicOrigin != beforeOrigin {
		t.Errorf("PublicOrigin = %q, want unchanged %q", cfg.PublicOrigin, beforeOrigin)
	}

	if cfg.ExternalBasePath != beforeBasePath {
		t.Errorf("ExternalBasePath = %q, want unchanged %q", cfg.ExternalBasePath, beforeBasePath)
	}
}

func TestOverlayAdminFlags(t *testing.T) {
	cfg := StrictConfig()
	username := "ops"
	password := "hunter2"

	overlayAdminFlags(cfg, FlagOverrides{
		AdminUsername: &username,
		AdminPassword: &password,
	})

	if cfg.Server.BootstrapAdmin.Username != username {
		t.Errorf("BootstrapAdmin.Username = %q, want %q", cfg.Server.BootstrapAdmin.Username, username)
	}

	if cfg.Server.BootstrapAdmin.Password != password {
		t.Errorf("BootstrapAdmin.Password = %q, want %q", cfg.Server.BootstrapAdmin.Password, password)
	}
}

func TestOverlayAdminFlags_SkipsNilAndEmpty(t *testing.T) {
	cfg := StrictConfig()
	beforeUser := cfg.Server.BootstrapAdmin.Username
	beforePass := cfg.Server.BootstrapAdmin.Password
	empty := ""

	overlayAdminFlags(cfg, FlagOverrides{
		AdminUsername: &empty,
		AdminPassword: nil,
	})

	if cfg.Server.BootstrapAdmin.Username != beforeUser {
		t.Errorf("BootstrapAdmin.Username = %q, want unchanged %q", cfg.Server.BootstrapAdmin.Username, beforeUser)
	}

	if cfg.Server.BootstrapAdmin.Password != beforePass {
		t.Errorf("BootstrapAdmin.Password = %q, want unchanged %q", cfg.Server.BootstrapAdmin.Password, beforePass)
	}
}

func TestOverlayLoggingFlags(t *testing.T) {
	cfg := StrictConfig()
	level := "warn"

	overlayLoggingFlags(cfg, FlagOverrides{
		LoggingLevel: &level,
	})

	if cfg.Logging.Level != level {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, level)
	}
}

func TestOverlayLoggingFlags_SkipsNilAndEmpty(t *testing.T) {
	cfg := StrictConfig()
	beforeLevel := cfg.Logging.Level
	empty := ""

	overlayLoggingFlags(cfg, FlagOverrides{
		LoggingLevel: &empty,
	})

	if cfg.Logging.Level != beforeLevel {
		t.Errorf("Logging.Level = %q, want unchanged %q", cfg.Logging.Level, beforeLevel)
	}
}

func TestOverlayTokenFlags(t *testing.T) {
	cfg := StrictConfig()
	path := "exchange/v1"

	overlayTokenFlags(cfg, FlagOverrides{
		TokenExchangePath: &path,
	})

	if cfg.TokenExchange.Path != path {
		t.Errorf("TokenExchange.Path = %q, want %q", cfg.TokenExchange.Path, path)
	}
}

func TestOverlayTokenFlags_SkipsNilAndEmpty(t *testing.T) {
	cfg := StrictConfig()
	beforePath := cfg.TokenExchange.Path
	empty := ""

	overlayTokenFlags(cfg, FlagOverrides{
		TokenExchangePath: &empty,
	})

	if cfg.TokenExchange.Path != beforePath {
		t.Errorf("TokenExchange.Path = %q, want unchanged %q", cfg.TokenExchange.Path, beforePath)
	}
}

func TestOverlayFlags_AllConcerns(t *testing.T) {
	cfg := StrictConfig()
	listen := ":8080"
	origin := "https://all.example"
	basePath := "/api"
	username := "admin"
	password := "secret"
	level := "debug"
	path := "token/custom"

	overlayFlags(cfg, FlagOverrides{
		ListenAddr:        &listen,
		PublicOrigin:      &origin,
		ExternalBasePath:  &basePath,
		AdminUsername:     &username,
		AdminPassword:     &password,
		LoggingLevel:      &level,
		TokenExchangePath: &path,
	})

	if cfg.ListenAddr != listen {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, listen)
	}

	if cfg.PublicOrigin != origin {
		t.Errorf("PublicOrigin = %q, want %q", cfg.PublicOrigin, origin)
	}

	if cfg.ExternalBasePath != basePath {
		t.Errorf("ExternalBasePath = %q, want %q", cfg.ExternalBasePath, basePath)
	}

	if cfg.Server.BootstrapAdmin.Username != username {
		t.Errorf("BootstrapAdmin.Username = %q, want %q", cfg.Server.BootstrapAdmin.Username, username)
	}

	if cfg.Server.BootstrapAdmin.Password != password {
		t.Errorf("BootstrapAdmin.Password = %q, want %q", cfg.Server.BootstrapAdmin.Password, password)
	}

	if cfg.Logging.Level != level {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, level)
	}

	if cfg.TokenExchange.Path != path {
		t.Errorf("TokenExchange.Path = %q, want %q", cfg.TokenExchange.Path, path)
	}
}
