// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package reason_test

import (
	"errors"
	"fmt"
	"testing"

	ocmreason "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	tsreason "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/reason"
)

type captureTB struct {
	testing.TB

	fatal bool
}

func (c *captureTB) Helper() {}

func (c *captureTB) Fatalf(_ string, _ ...any) {
	c.fatal = true

	panic("captureTB.Fatalf")
}

func expectFatal(t *testing.T, fn func(testing.TB)) {
	t.Helper()
	stub := &captureTB{TB: t}

	defer func() {
		if recover() == nil {
			t.Fatal("expected Fatalf")
		}

		if !stub.fatal {
			t.Fatal("expected Fatalf")
		}
	}()

	fn(stub)
}

func TestAssertClassifiedReason_matchingReason(t *testing.T) {
	err := ocmreason.NewClassifiedError(ocmreason.ReasonSignatureInvalid, "bad signature", nil)
	tsreason.AssertClassifiedReason(t, err, ocmreason.ReasonSignatureInvalid)
}

func TestAssertClassifiedReason_wrappedClassifiedError(t *testing.T) {
	classifiedErr := ocmreason.NewClassifiedError(ocmreason.ReasonSignatureInvalid, "bad signature", nil)
	wrapped := fmt.Errorf("outer: %w", classifiedErr)
	tsreason.AssertClassifiedReason(t, wrapped, ocmreason.ReasonSignatureInvalid)
}

func TestAssertClassifiedReason_nilError(t *testing.T) {
	expectFatal(t, func(tb testing.TB) {
		tsreason.AssertClassifiedReason(tb, nil, ocmreason.ReasonSignatureInvalid)
	})
}

func TestAssertClassifiedReason_notClassified(t *testing.T) {
	expectFatal(t, func(tb testing.TB) {
		tsreason.AssertClassifiedReason(tb, errors.New("plain error"), ocmreason.ReasonSignatureInvalid)
	})
}

func TestAssertClassifiedReason_wrongReason(t *testing.T) {
	err := ocmreason.NewClassifiedError(ocmreason.ReasonDigestMismatch, "digest mismatch", nil)

	expectFatal(t, func(tb testing.TB) {
		tsreason.AssertClassifiedReason(tb, err, ocmreason.ReasonSignatureInvalid)
	})
}
