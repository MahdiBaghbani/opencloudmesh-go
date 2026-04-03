package reason_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
)

func TestReasonMappings(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		wantOCM    int
		wantAPI    int
		wantVerify string
	}{
		{
			name:       "peer discovery failed",
			code:       reason.PeerDiscoveryFailed,
			wantOCM:    http.StatusServiceUnavailable,
			wantAPI:    http.StatusBadGateway,
			wantVerify: "discovery_failed",
		},
		{
			name:       "peer discovery disabled",
			code:       reason.PeerDiscoveryDisabled,
			wantOCM:    http.StatusServiceUnavailable,
			wantAPI:    http.StatusNotImplemented,
			wantVerify: "discovery_disabled",
		},
		{
			name:       "peer policy unsatisfied",
			code:       reason.PeerPolicyUnsatisfied,
			wantOCM:    http.StatusForbidden,
			wantAPI:    http.StatusForbidden,
			wantVerify: "policy_denied",
		},
		{
			name:       "peer capability mismatch",
			code:       reason.PeerCapabilityMismatch,
			wantOCM:    http.StatusNotImplemented,
			wantAPI:    http.StatusBadRequest,
			wantVerify: "capability_mismatch",
		},
		{
			name:       "peer unreachable",
			code:       reason.PeerUnreachable,
			wantOCM:    http.StatusServiceUnavailable,
			wantAPI:    http.StatusBadGateway,
			wantVerify: "unreachable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reason.OCMStatus(tt.code); got != tt.wantOCM {
				t.Fatalf("OCMStatus(%q)=%d, want %d", tt.code, got, tt.wantOCM)
			}
			if got := reason.APIStatus(tt.code); got != tt.wantAPI {
				t.Fatalf("APIStatus(%q)=%d, want %d", tt.code, got, tt.wantAPI)
			}
			if got := reason.VerifyCode(tt.code); got != tt.wantVerify {
				t.Fatalf("VerifyCode(%q)=%q, want %q", tt.code, got, tt.wantVerify)
			}
		})
	}
}

func TestFromPeerCompat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "discovery failed", in: peercompat.ReasonDiscoveryFailed, want: reason.PeerDiscoveryFailed},
		{name: "peer capability missing", in: peercompat.ReasonPeerCapabilityMissing, want: reason.PeerCapabilityMismatch},
		{name: "signature required", in: peercompat.ReasonSignatureRequired, want: reason.PeerPolicyUnsatisfied},
		{name: "signature invalid", in: peercompat.ReasonSignatureInvalid, want: reason.PeerPolicyUnsatisfied},
		{name: "ssrf blocked", in: peercompat.ReasonSSRFBlocked, want: reason.PeerPolicyUnsatisfied},
		{name: "network error", in: peercompat.ReasonNetworkError, want: reason.PeerUnreachable},
		{name: "tls error", in: peercompat.ReasonTLSError, want: reason.PeerUnreachable},
		{name: "unknown", in: peercompat.ReasonUnknown, want: reason.PeerUnreachable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reason.FromPeerCompat(tt.in); got != tt.want {
				t.Fatalf("FromPeerCompat(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCanonicalFromError(t *testing.T) {
	t.Run("passes through reason.Error", func(t *testing.T) {
		err := reason.New(reason.PeerDiscoveryDisabled, "disabled", nil)
		if got := reason.CanonicalFromError(err); got != reason.PeerDiscoveryDisabled {
			t.Fatalf("CanonicalFromError()=%q, want %q", got, reason.PeerDiscoveryDisabled)
		}
	})

	t.Run("maps classified peercompat errors", func(t *testing.T) {
		err := peercompat.NewClassifiedError(peercompat.ReasonSignatureRequired, "missing signature", nil)
		if got := reason.CanonicalFromError(err); got != reason.PeerPolicyUnsatisfied {
			t.Fatalf("CanonicalFromError()=%q, want %q", got, reason.PeerPolicyUnsatisfied)
		}
	})

	t.Run("maps unknown errors to peer unreachable", func(t *testing.T) {
		err := errors.New("some opaque error")
		if got := reason.CanonicalFromError(err); got != reason.PeerUnreachable {
			t.Fatalf("CanonicalFromError()=%q, want %q", got, reason.PeerUnreachable)
		}
	})
}
