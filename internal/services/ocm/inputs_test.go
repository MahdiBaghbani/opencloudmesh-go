package ocm

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
	if in.IncomingShareRepo != nil || in.OutgoingShareRepo != nil || in.OutgoingInviteRepo != nil {
		t.Fatal("zero Inputs should have nil repo fields")
	}
	if in.PartyRepo != nil || in.PolicyEngine != nil || in.DiscoveryClient != nil {
		t.Fatal("zero Inputs should have nil identity/discovery fields")
	}
	if in.OpenCloudMeshPolicy != nil || in.RuntimePolicy != nil || in.PeerContract != nil {
		t.Fatal("zero Inputs should have nil policy fields")
	}
	if in.TokenStore != nil || in.SignatureMiddleware != nil {
		t.Fatal("zero Inputs should have nil token/signature fields")
	}
	if in.LocalProviderFQDN != "" || in.LocalProviderFQDNForCompare != "" ||
		in.PublicOrigin != "" || in.PublicScheme != "" || in.TokenExchangePath != "" {
		t.Fatal("zero Inputs should have empty string fields")
	}
}
