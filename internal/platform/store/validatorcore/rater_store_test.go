// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestLoadSpecificationRating_RejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	configured := &Core{db: &gorm.DB{}}

	cases := []struct {
		name    string
		core    *Core
		run     *TestRun
		wantErr error
	}{
		{
			name:    "nil core",
			core:    nil,
			run:     &TestRun{TestRunID: "run-rate"},
			wantErr: ErrStoreNotConfigured,
		},
		{
			name:    "nil db",
			core:    &Core{},
			run:     &TestRun{TestRunID: "run-rate"},
			wantErr: ErrStoreNotConfigured,
		},
		{
			name:    "nil run",
			core:    configured,
			run:     nil,
			wantErr: ErrNilTestRun,
		},
		{
			name:    "empty test run id",
			core:    configured,
			run:     &TestRun{},
			wantErr: ErrEmptyTestRunID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, evidence, err := tc.core.LoadSpecificationRating(t.Context(), tc.run)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}

			if evidence != nil {
				t.Fatalf("evidence = %#v, want nil", evidence)
			}
		})
	}
}
