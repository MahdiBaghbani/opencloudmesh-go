// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"reflect"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	apisvc "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	validatorsvc "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/validator"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// In validator mode the production wiring installs the forward-share dispatch
// hook on the API service's outgoing-share handler; in generic mode the hook
// seat stays empty and the generic flow is unchanged.
func TestBuildCoreServices_ValidatorModeInstallsOutgoingDispatchHook(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.DataDir = t.TempDir()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Cleanup(func() {
		if result.StopRetentionSweep != nil {
			result.StopRetentionSweep()
		}

		if closeErr := result.Persistence.Close(); closeErr != nil {
			t.Errorf("Persistence.Close: %v", closeErr)
		}
	})

	if result.Deps.ValidatorStore == nil {
		t.Fatal("expected validator store in validator mode")
	}

	services, err := wiring.BuildCoreServices(cfg, tslog.DiscardLogger(), result.Deps)
	if err != nil {
		t.Fatalf("BuildCoreServices: %v", err)
	}

	hook := outgoingDispatchHook(t, services)
	if hook.IsNil() {
		t.Fatal("validator mode must install the outgoing dispatch hook")
	}

	if got := hook.Elem().Type().String(); got != "*forwardshare.Service" {
		t.Fatalf("dispatch hook type = %s, want *forwardshare.Service", got)
	}

	validatorSvc, ok := services["validator"].(*validatorsvc.Service)
	if !ok {
		t.Fatalf("validator service is %T, not *validator.Service", services["validator"])
	}

	if validatorSvc.ActiveRunner() == nil {
		t.Fatal("validator mode must start the active runner")
	}

	apiSvc, ok := services["api"].(*apisvc.Service)
	if !ok {
		t.Fatalf("api service is %T, not *api.Service", services["api"])
	}

	if apiSvc.OutgoingShareHandler() == nil {
		t.Fatal("validator mode must expose the outgoing share handler")
	}

	if closeErr := validatorSvc.Close(); closeErr != nil {
		t.Fatalf("validator.Close: %v", closeErr)
	}
}

func TestBuildCoreServices_GenericModeLeavesDispatchHookEmpty(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	cfg.Persistence.DataDir = t.TempDir()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Cleanup(func() {
		if result.StopRetentionSweep != nil {
			result.StopRetentionSweep()
		}

		if closeErr := result.Persistence.Close(); closeErr != nil {
			t.Errorf("Persistence.Close: %v", closeErr)
		}
	})

	if result.Deps.ValidatorStore != nil {
		t.Fatal("generic mode must not build a validator store")
	}

	services, err := wiring.BuildCoreServices(cfg, tslog.DiscardLogger(), result.Deps)
	if err != nil {
		t.Fatalf("BuildCoreServices: %v", err)
	}

	if hook := outgoingDispatchHook(t, services); !hook.IsNil() {
		t.Fatal("generic mode must leave the dispatch hook seat empty")
	}
}

// outgoingDispatchHook reads the installed hook off the API service's
// outgoing-share handler. The field is private by design; the wiring contract
// is verified through reflection, the same strategy the crypto wiring tests
// use for private handler fields.
func outgoingDispatchHook(t *testing.T, services map[string]service.Service) reflect.Value {
	t.Helper()

	apiSvc, ok := services["api"].(*apisvc.Service)
	if !ok {
		t.Fatalf("api service is %T, not *api.Service", services["api"])
	}

	outgoingHandler := reflect.ValueOf(apiSvc).Elem().FieldByName("outgoingHandler")
	if outgoingHandler.IsNil() {
		t.Fatal("outgoing shares handler is nil")
	}

	return outgoingHandler.Elem().FieldByName("dispatchHook")
}
