// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestMustIncludeTokenExchange(t *testing.T) {
	strictFacts := policy.NewCodeFlow().Evaluate()
	voluntaryFacts := policy.Facts{IncludesTokenExchangeRequirement: false}
	forcedDisc := &spec.Discovery{Criteria: []string{spec.CriteriaMustExchangeToken}}
	relaxedDisc := &spec.Discovery{Criteria: []string{}}

	tests := []struct {
		name  string
		facts policy.Facts
		disc  *spec.Discovery
		want  bool
	}{
		{
			name:  "strict facts require token exchange",
			facts: strictFacts,
			disc:  relaxedDisc,
			want:  true,
		},
		{
			name:  "voluntary facts without peer force",
			facts: voluntaryFacts,
			disc:  relaxedDisc,
			want:  false,
		},
		{
			name:  "peer force overrides voluntary facts",
			facts: voluntaryFacts,
			disc:  forcedDisc,
			want:  true,
		},
		{
			name:  "nil discovery falls back to facts",
			facts: strictFacts,
			disc:  nil,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustIncludeTokenExchange(tt.facts, tt.disc)
			if got != tt.want {
				t.Errorf("mustIncludeTokenExchange(%+v, %v) = %v, want %v",
					tt.facts, tt.disc, got, tt.want)
			}
		})
	}
}

func TestTokenExchangeRequirements(t *testing.T) {
	if got := tokenExchangeRequirements(true); len(got) != 1 || got[0] != spec.RequirementMustExchangeToken {
		t.Errorf("tokenExchangeRequirements(true) = %v, want [%s]", got, spec.RequirementMustExchangeToken)
	}

	if got := tokenExchangeRequirements(false); got != nil {
		t.Errorf("tokenExchangeRequirements(false) = %v, want nil", got)
	}
}
