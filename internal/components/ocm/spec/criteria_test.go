// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestCriteriaWireValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "must-use-http-sig", got: spec.CriteriaMustUseHTTPSig, want: "must-use-http-sig"},
		{name: "must-exchange-token", got: spec.CriteriaMustExchangeToken, want: "must-exchange-token"},
		{name: "denylist", got: spec.CriteriaDenylist, want: "denylist"},
		{name: "allowlist", got: spec.CriteriaAllowlist, want: "allowlist"},
		{name: "must-invite", got: spec.CriteriaMustInvite, want: "must-invite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("wire value = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestDiscoveryHelpersUseCriteriaConstants(t *testing.T) {
	disc := &spec.Discovery{
		Criteria: []string{spec.CriteriaMustUseHTTPSig, spec.CriteriaMustExchangeToken},
	}
	if !disc.RequiresHTTPSig() {
		t.Error("RequiresHTTPSig() = false, want true")
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("HasCriteria(CriteriaMustExchangeToken) = false, want true")
	}

	if disc.HasCriteria("unknown") {
		t.Error("HasCriteria(unknown) = true, want false")
	}
}

// criteriaClosedPathFiles are production files on the closed migration path.
// Each must not contain raw criteria wire string literals; use spec.*.
var criteriaClosedPathFiles = []string{
	"internal/components/ocm/spec/discovery.go",
	"internal/components/ocm/discovery/builder.go",
	"internal/components/ocm/policy/compiler.go",
}

var criteriaWireLiterals = []string{
	`"must-use-http-sig"`,
	`"must-exchange-token"`,
	`"denylist"`,
	`"allowlist"`,
	`"must-invite"`,
}

func TestCriteriaClosedPathNoRawWireLiterals(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for _, rel := range criteriaClosedPathFiles {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			content := string(data)
			for _, lit := range criteriaWireLiterals {
				if strings.Contains(content, lit) {
					t.Errorf("%s still contains raw criteria literal %s; use spec.*", rel, lit)
				}
			}
		})
	}
}
