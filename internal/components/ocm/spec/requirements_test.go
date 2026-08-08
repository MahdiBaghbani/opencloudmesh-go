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

func TestRequirementWireValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "must-exchange-token", got: spec.RequirementMustExchangeToken, want: "must-exchange-token"},
		{name: "must-use-mfa", got: spec.RequirementMustUseMFA, want: "must-use-mfa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.got != tc.want {
				t.Errorf("wire value = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

func TestWebDAVHasRequirementUsesConstant(t *testing.T) {
	t.Parallel()

	p := &spec.WebDAVProtocol{
		Requirements: []string{spec.RequirementMustExchangeToken},
	}
	if !p.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Error("HasRequirement(RequirementMustExchangeToken) = false, want true")
	}

	if p.HasRequirement(spec.RequirementMustUseMFA) {
		t.Error("HasRequirement(RequirementMustUseMFA) = true, want false")
	}
}

func TestWebappHasRequirementUsesConstant(t *testing.T) {
	t.Parallel()

	p := &spec.WebappProtocol{
		Requirements: []string{spec.RequirementMustExchangeToken},
	}
	if !p.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Error("HasRequirement(RequirementMustExchangeToken) = false, want true")
	}

	if p.HasRequirement(spec.RequirementMustUseMFA) {
		t.Error("HasRequirement(RequirementMustUseMFA) = true, want false")
	}
}

// requirementClosedPathFiles are production files on the closed migration path.
// Each must not contain raw requirement wire string literals; use spec.*.
var requirementClosedPathFiles = []string{
	"internal/components/ocm/spec/shares.go",
	"internal/components/ocm/spec/protocol_admission.go",
	"internal/components/ocm/access/remote.go",
	"internal/components/ocm/shares/incoming/handler.go",
	"internal/components/ocm/policy/compiler.go",
}

var requirementWireLiterals = []string{
	`"must-exchange-token"`,
	`"must-use-mfa"`,
}

func TestRequirementClosedPathNoRawWireLiterals(t *testing.T) {
	t.Parallel()

	root := modroot.ModuleRoot(t)
	for _, rel := range requirementClosedPathFiles {
		t.Run(rel, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			content := string(data)
			for _, lit := range requirementWireLiterals {
				if strings.Contains(content, lit) {
					t.Errorf("%s still contains raw requirement literal %s; use spec.*", rel, lit)
				}
			}
		})
	}
}
