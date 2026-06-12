package ocmaux

import (
	"reflect"
	"testing"
)

func TestInputs_FrozenShape(t *testing.T) {
	typ := reflect.TypeOf(Inputs{})
	if typ.NumField() != 4 {
		t.Fatalf("Inputs field count = %d, want 4 frozen fields", typ.NumField())
	}

	var in Inputs
	if in.TrustGroupMgr != nil || in.DiscoveryClient != nil || in.InterceptorProfiles != nil {
		t.Fatal("zero Inputs should have nil trust/discovery/profile fields")
	}
}
