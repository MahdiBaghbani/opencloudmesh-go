package wiring_test

import (
	"reflect"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func TestWiringSkeleton_BuildOptsIsDefinedInWiring(t *testing.T) {
	var opts wiring.BuildOpts
	if reflect.TypeOf(opts).PkgPath() != "github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring" {
		t.Fatalf("BuildOpts must be defined in wiring, got package %q", reflect.TypeOf(opts).PkgPath())
	}
}

func TestWiringSkeleton_BuildResultIsDefinedInWiring(t *testing.T) {
	var result wiring.BuildResult
	if reflect.TypeOf(result).PkgPath() != "github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring" {
		t.Fatalf("BuildResult must be defined in wiring, got package %q", reflect.TypeOf(result).PkgPath())
	}
	if reflect.TypeOf(result.Deps).Elem().Name() != "Deps" {
		t.Fatalf("BuildResult.Deps must be *wiring.Deps, got %v", reflect.TypeOf(result.Deps))
	}
}
