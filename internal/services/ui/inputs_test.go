package ui

import (
	"reflect"
	"testing"
)

func TestInputs_FrozenShape(t *testing.T) {
	typ := reflect.TypeOf(Inputs{})
	if typ.NumField() != 2 {
		t.Fatalf("Inputs field count = %d, want 2 frozen fields", typ.NumField())
	}

	var in Inputs
	if in.ExternalBasePath != "" || in.LocalProviderFQDN != "" {
		t.Fatal("zero Inputs should have empty string fields")
	}
}
