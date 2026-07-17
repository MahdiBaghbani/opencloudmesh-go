package peer

import (
	"net/http/httptest"
	"testing"
)

func TestResolveSharesRequest_SenderPreferred(t *testing.T) {
	body := []byte(`{"sender":"alice@sender.example","owner":"bob@owner.example"}`)
	r := httptest.NewRequest("POST", "/ocm/shares", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveSharesRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "sender.example" {
		t.Errorf("got %q, want %q", got, "sender.example")
	}
}

func TestResolveSharesRequest_FallbackToOwner(t *testing.T) {
	body := []byte(`{"sender":"","owner":"bob@owner.example:9200"}`)
	r := httptest.NewRequest("POST", "/ocm/shares", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveSharesRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "owner.example:9200" {
		t.Errorf("got %q, want %q", got, "owner.example:9200")
	}
}

func TestResolveSharesRequest_LastAtSemantics(t *testing.T) {
	// Email-style identifier with @ in the identifier part
	body := []byte(`{"sender":"alice@university.edu@provider.net"}`)
	r := httptest.NewRequest("POST", "/ocm/shares", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveSharesRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "provider.net" {
		t.Errorf("got %q, want %q (last-@ semantics)", got, "provider.net")
	}
}

func TestResolveSharesRequest_NoSenderOrOwner(t *testing.T) {
	body := []byte(`{"sender":"","owner":""}`)
	r := httptest.NewRequest("POST", "/ocm/shares", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveSharesRequest(r, body)
	if err == nil {
		t.Error("expected error for empty sender and owner")
	}
}

func TestResolveSharesRequest_InvalidJSON(t *testing.T) {
	body := []byte(`{invalid}`)
	r := httptest.NewRequest("POST", "/ocm/shares", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveSharesRequest(r, body)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestResolveRequestShareRequest_ExtractsFromShareWith(t *testing.T) {
	body := []byte(`{"owner":"527bd5b5d689e2c32ae974c6229ff785@apiwise.nl","shareWith":"51dc30ddc473d43a6011e9ebba6ca770@geant.org","share":"1234567890abcdef"}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveRequestShareRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "geant.org" {
		t.Errorf("got %q, want %q", got, "geant.org")
	}
}

func TestResolveRequestShareRequest_IgnoresOwnerField(t *testing.T) {
	// The RequestShare schema has no sender; the resolver must key off
	// shareWith even when owner (a different party) is also present.
	body := []byte(`{"owner":"alice@owner.example","shareWith":"bob@shareWith.example","share":"1"}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveRequestShareRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "shareWith.example" {
		t.Errorf("got %q, want %q", got, "shareWith.example")
	}
}

func TestResolveRequestShareRequest_LastAtSemantics(t *testing.T) {
	body := []byte(`{"shareWith":"alice@university.edu@provider.net"}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveRequestShareRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "provider.net" {
		t.Errorf("got %q, want %q (last-@ semantics)", got, "provider.net")
	}
}

func TestResolveRequestShareRequest_MissingShareWith(t *testing.T) {
	body := []byte(`{"owner":"alice@owner.example","share":"1"}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveRequestShareRequest(r, body)
	if err == nil {
		t.Error("expected error for missing shareWith")
	}
}

func TestResolveRequestShareRequest_RejectsURLShapedShareWith(t *testing.T) {
	body := []byte(`{"shareWith":"alice@https://provider.example"}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveRequestShareRequest(r, body)
	if err == nil {
		t.Fatal("expected error for URL-shaped shareWith provider")
	}
}

func TestResolveRequestShareRequest_InvalidJSON(t *testing.T) {
	body := []byte(`{invalid}`)
	r := httptest.NewRequest("POST", "/ocm/request-share", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveRequestShareRequest(r, body)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestResolveInviteAcceptedRequest(t *testing.T) {
	body := []byte(`{"recipientProvider":"recipient.example:443","token":"abc","userID":"u"}`)
	r := httptest.NewRequest("POST", "/ocm/invite-accepted", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveInviteAcceptedRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "recipient.example:443" {
		t.Errorf("got %q, want %q", got, "recipient.example:443")
	}
}

func TestResolveInviteAcceptedRequest_MissingProvider(t *testing.T) {
	body := []byte(`{"recipientProvider":""}`)
	r := httptest.NewRequest("POST", "/ocm/invite-accepted", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveInviteAcceptedRequest(r, body)
	if err == nil {
		t.Error("expected error for empty recipientProvider")
	}
}

func TestResolveInviteAcceptedRequest_RejectsURLShapedProvider(t *testing.T) {
	body := []byte(`{"recipientProvider":"https://recipient.example","token":"abc","userID":"u"}`)
	r := httptest.NewRequest("POST", "/ocm/invite-accepted", nil)

	resolver := NewResolver()
	_, err := resolver.ResolveInviteAcceptedRequest(r, body)
	if err == nil {
		t.Fatal("expected error for URL-shaped recipientProvider")
	}
}

func TestResolveNotificationsRequest_ReturnsEmpty(t *testing.T) {
	body := []byte(`{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"abc123"}`)
	r := httptest.NewRequest("POST", "/ocm/notifications", nil)

	resolver := NewResolver()
	got, err := resolver.ResolveNotificationsRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestResolveTokenRequest_FormBody(t *testing.T) {
	body := []byte(`grant_type=authorization_code&client_id=receiver.example.com%3A443&code=abc`)
	r := httptest.NewRequest("POST", "/ocm/token", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resolver := NewResolver()
	got, err := resolver.ResolveTokenRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "receiver.example.com:443" {
		t.Errorf("got %q, want %q", got, "receiver.example.com:443")
	}
}

func TestResolveTokenRequest_JSONBody(t *testing.T) {
	body := []byte(`{"grant_type":"authorization_code","client_id":"receiver.example.com","code":"abc"}`)
	r := httptest.NewRequest("POST", "/ocm/token", nil)
	r.Header.Set("Content-Type", "application/json")

	resolver := NewResolver()
	got, err := resolver.ResolveTokenRequest(r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "receiver.example.com" {
		t.Errorf("got %q, want %q", got, "receiver.example.com")
	}
}

func TestResolveTokenRequest_MissingClientID(t *testing.T) {
	body := []byte(`grant_type=authorization_code&code=abc`)
	r := httptest.NewRequest("POST", "/ocm/token", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resolver := NewResolver()
	_, err := resolver.ResolveTokenRequest(r, body)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestResolveTokenRequest_RejectsURLShapedClientID(t *testing.T) {
	body := []byte(`grant_type=authorization_code&client_id=https%3A%2F%2Freceiver.example.com&code=abc`)
	r := httptest.NewRequest("POST", "/ocm/token", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resolver := NewResolver()
	_, err := resolver.ResolveTokenRequest(r, body)
	if err == nil {
		t.Fatal("expected error for URL-shaped client_id")
	}
}
