package api

import (
	"reflect"
	"testing"
)

func TestInputs_FrozenShape(t *testing.T) {
	typ := reflect.TypeOf(Inputs{})
	if typ.NumField() != 16 {
		t.Fatalf("Inputs field count = %d, want 16 frozen fields", typ.NumField())
	}

	var in Inputs
	if in.PartyRepo != nil || in.SessionRepo != nil || in.UserAuth != nil {
		t.Fatal("zero Inputs should have nil identity fields")
	}
	if in.HTTPClient != nil || in.DiscoveryClient != nil || in.Signer != nil {
		t.Fatal("zero Inputs should have nil client/crypto fields")
	}
	if in.OutboundPolicy != nil || in.OpenCloudMeshPolicy != nil || in.PeerContract != nil {
		t.Fatal("zero Inputs should have nil policy fields")
	}
	if in.LocalProviderFQDN != "" || in.InterceptorProfiles != nil {
		t.Fatal("zero Inputs should have empty provider/interceptor fields")
	}
}
