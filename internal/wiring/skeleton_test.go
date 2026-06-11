package wiring_test

import (
	"reflect"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func TestWiringSkeleton_BuildOptsAliasesWireOptions(t *testing.T) {
	var opts wiring.BuildOpts
	var wireOpts app.WireOptions
	if reflect.TypeOf(opts) != reflect.TypeOf(wireOpts) {
		t.Fatalf("BuildOpts type %v, want alias of app.WireOptions %v",
			reflect.TypeOf(opts), reflect.TypeOf(wireOpts))
	}
}

func TestWiringSkeleton_BuildResultAliasesBootstrapResult(t *testing.T) {
	var result wiring.BuildResult
	var bootstrapResult app.BootstrapResult
	if reflect.TypeOf(result) != reflect.TypeOf(bootstrapResult) {
		t.Fatalf("BuildResult type %v, want alias of app.BootstrapResult %v",
			reflect.TypeOf(result), reflect.TypeOf(bootstrapResult))
	}
}
