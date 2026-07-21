package api

import (
	"strings"
	"testing"
)

func TestValidateInputs_ReportsMissingRequiredFields(t *testing.T) {
	base := testAPIInputs()

	tests := []struct {
		name    string
		mutate  func(*Inputs)
		wantSub string
	}{
		{
			name:    "PartyRepo",
			mutate:  func(in *Inputs) { in.PartyRepo = nil },
			wantSub: "PartyRepo is required",
		},
		{
			name:    "SessionRepo",
			mutate:  func(in *Inputs) { in.SessionRepo = nil },
			wantSub: "SessionRepo is required",
		},
		{
			name:    "UserAuth",
			mutate:  func(in *Inputs) { in.UserAuth = nil },
			wantSub: "UserAuth is required",
		},
		{
			name:    "HTTPClient",
			mutate:  func(in *Inputs) { in.HTTPClient = nil },
			wantSub: "HTTPClient is required",
		},
		{
			name:    "DiscoveryClient",
			mutate:  func(in *Inputs) { in.DiscoveryClient = nil },
			wantSub: "DiscoveryClient is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base
			tt.mutate(&in)
			err := validateInputs(in)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}
