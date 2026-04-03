package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestRuntimePolicyStrictIncomingSharePayloadValidation(t *testing.T) {
	tests := []struct {
		name          string
		inboundMode   string
		authenticated bool
		want          bool
	}{
		{
			name:          "strict always validates strictly",
			inboundMode:   "strict",
			authenticated: false,
			want:          true,
		},
		{
			name:          "strict stays strict for authenticated peers",
			inboundMode:   "strict",
			authenticated: true,
			want:          true,
		},
		{
			name:          "lenient keeps unauthenticated peers non-strict",
			inboundMode:   "lenient",
			authenticated: false,
			want:          false,
		},
		{
			name:          "lenient validates authenticated peers strictly",
			inboundMode:   "lenient",
			authenticated: true,
			want:          true,
		},
		{
			name:          "off keeps non-strict path",
			inboundMode:   "off",
			authenticated: true,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DevConfig()
			cfg.Signature.InboundMode = tt.inboundMode

			got := policy.NewRuntimePolicy(cfg).StrictIncomingSharePayloadValidation(tt.authenticated)
			if got != tt.want {
				t.Fatalf("StrictIncomingSharePayloadValidation() = %v, want %v", got, tt.want)
			}
		})
	}
}
