// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestValidatePreBootstrap_UnknownServiceName(t *testing.T) {
	cfg := config.DevConfig()

	cfg.HTTP.Services = map[string]map[string]any{
		"bogus": {},
	}
	if err := ValidatePreBootstrap(cfg); err == nil {
		t.Fatal("ValidatePreBootstrap() = nil, want error for unknown service")
	}
}

func TestValidatePreBootstrap_ValidServices(t *testing.T) {
	cfg := config.DevConfig()

	cfg.HTTP.Services = map[string]map[string]any{
		"api": {},
	}
	if err := ValidatePreBootstrap(cfg); err != nil {
		t.Fatalf("ValidatePreBootstrap() = %v, want nil", err)
	}
}

func TestValidateBuiltServices_HappyPath(t *testing.T) {
	if err := ValidateBuiltServices(allBuiltServices()); err != nil {
		t.Fatalf("ValidateBuiltServices() = %v, want nil", err)
	}
}

func TestValidateBuiltServices_CountMismatch(t *testing.T) {
	services := allBuiltServices()
	delete(services, "api")

	err := ValidateBuiltServices(services)
	if err == nil {
		t.Fatal("ValidateBuiltServices() = nil, want count mismatch error")
	}

	if !strings.Contains(err.Error(), "built service count = 5, want 6 from descriptor table") {
		t.Fatalf("ValidateBuiltServices() error = %q, want count mismatch message", err)
	}
}

func TestValidateBuiltServices_MissingService(t *testing.T) {
	services := allBuiltServices()
	delete(services, "webdav")
	services["bogus"] = &descriptorStub{prefix: "bogus"}

	err := ValidateBuiltServices(services)
	if err == nil {
		t.Fatal("ValidateBuiltServices() = nil, want missing service error")
	}

	if !strings.Contains(err.Error(), `missing built service "webdav"`) {
		t.Fatalf("ValidateBuiltServices() error = %q, want missing service message", err)
	}
}

func TestValidateBuiltServices_ExtraService(t *testing.T) {
	services := allBuiltServices()
	services["bogus"] = &descriptorStub{prefix: "bogus"}

	err := ValidateBuiltServices(services)
	if err == nil {
		t.Fatal("ValidateBuiltServices() = nil, want extra service error")
	}

	if !strings.Contains(err.Error(), `built service "bogus" has no descriptor`) {
		t.Fatalf("ValidateBuiltServices() error = %q, want extra service message", err)
	}
}

func TestValidateBuiltServices_NilService(t *testing.T) {
	services := allBuiltServices()
	services["api"] = nil

	err := ValidateBuiltServices(services)
	if err == nil {
		t.Fatal("ValidateBuiltServices() = nil, want nil service error")
	}

	if !strings.Contains(err.Error(), `built service "api" is nil`) {
		t.Fatalf("ValidateBuiltServices() error = %q, want nil service message", err)
	}
}

func TestValidateBuiltServices_PrefixMismatch(t *testing.T) {
	services := allBuiltServices()
	services["ocmaux"] = &descriptorStub{prefix: "wrong"}

	err := ValidateBuiltServices(services)
	if err == nil {
		t.Fatal("ValidateBuiltServices() = nil, want prefix mismatch error")
	}

	want := `service "ocmaux" prefix = "wrong", want descriptor prefix "ocm-aux"`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateBuiltServices() error = %q, want %q", err, want)
	}
}

func allBuiltServices() map[string]Service {
	out := make(map[string]Service, len(descriptors))
	for _, d := range descriptors {
		out[d.Name] = &descriptorStub{prefix: d.Prefix}
	}

	return out
}

type descriptorStub struct {
	prefix string
}

func (s *descriptorStub) Handler() http.Handler { return nil }
func (s *descriptorStub) Prefix() string        { return s.prefix }
func (s *descriptorStub) Close() error          { return nil }
