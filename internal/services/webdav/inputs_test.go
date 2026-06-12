package webdav

import (
	"reflect"
	"testing"
)

func TestInputs_FrozenShape(t *testing.T) {
	typ := reflect.TypeOf(Inputs{})
	if typ.NumField() != 3 {
		t.Fatalf("Inputs field count = %d, want 3 frozen fields", typ.NumField())
	}

	var in Inputs
	if in.OutgoingShareRepo != nil || in.TokenStore != nil || in.PeerContract != nil {
		t.Fatal("zero Inputs should have nil repo/policy fields")
	}
}
