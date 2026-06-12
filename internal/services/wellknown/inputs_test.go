package wellknown

import (
	"reflect"
	"testing"
)

func TestInputs_FrozenShape(t *testing.T) {
	typ := reflect.TypeOf(Inputs{})
	if typ.NumField() != 1 {
		t.Fatalf("Inputs field count = %d, want 1 frozen field", typ.NumField())
	}
}
