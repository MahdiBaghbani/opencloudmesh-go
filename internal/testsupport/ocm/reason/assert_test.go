// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
	t.Parallel()

	err := ocmreason.NewClassifiedError(ocmreason.ReasonSignatureInvalid, "bad signature", nil)
	tsreason.AssertClassifiedReason(t, err, ocmreason.ReasonSignatureInvalid)
}

func TestAssertClassifiedReason_wrappedClassifiedError(t *testing.T) {
	t.Parallel()

	classifiedErr := ocmreason.NewClassifiedError(ocmreason.ReasonSignatureInvalid, "bad signature", nil)
	wrapped := fmt.Errorf("outer: %w", classifiedErr)
	tsreason.AssertClassifiedReason(t, wrapped, ocmreason.ReasonSignatureInvalid)
}

func TestAssertClassifiedReason_nilError(t *testing.T) {
	t.Parallel()
	expectFatal(t, func(tb testing.TB) {
		tb.Helper()
		tsreason.AssertClassifiedReason(tb, nil, ocmreason.ReasonSignatureInvalid)
	})
}

func TestAssertClassifiedReason_notClassified(t *testing.T) {
	t.Parallel()
	expectFatal(t, func(tb testing.TB) {
		tb.Helper()
		tsreason.AssertClassifiedReason(tb, errors.New("plain error"), ocmreason.ReasonSignatureInvalid)
	})
}

func TestAssertClassifiedReason_wrongReason(t *testing.T) {
	t.Parallel()

	err := ocmreason.NewClassifiedError(ocmreason.ReasonDigestMismatch, "digest mismatch", nil)

	expectFatal(t, func(tb testing.TB) {
		tb.Helper()
		tsreason.AssertClassifiedReason(tb, err, ocmreason.ReasonSignatureInvalid)
	})
}
