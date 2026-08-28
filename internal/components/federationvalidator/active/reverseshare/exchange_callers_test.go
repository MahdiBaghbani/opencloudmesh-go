// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProductionActiveExchangeCallersExist(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	here := filepath.Dir(thisFile)
	want := map[string][]string{
		filepath.Join(here, "service.go"): {
			"IncomingSharesExchange", "PersistActiveExchangeAndFact",
		},
		filepath.Join(here, "observe_capability.go"): {
			"IncomingTokenExchange", "IncomingWebDAVExchange", "PersistActiveExchange",
		},
		filepath.Join(here, "observe_notification.go"): {
			"IncomingNotificationExchange", "PersistActiveExchangeAndFact",
		},
		filepath.Join(here, "..", "forwardshare", "dispatch.go"): {
			"OutgoingSharesExchange", "PersistActiveExchangeAndFact",
		},
		filepath.Join(here, "..", "reverseinvite", "decorator.go"): {
			"IncomingInviteAcceptedExchange", "PersistActiveExchangeAndFact",
		},
		filepath.Join(here, "..", "reverseinvite", "accept.go"): {
			"OutgoingInviteAcceptedExchange", "PersistActiveExchangeAndFact",
			"ReverseInviteAcceptedFact",
		},
		filepath.Join(here, "..", "..", "..", "..", "platform", "store", "validatorcore", "exchange_persist.go"): {
			"InsertReportExchange",
		},
	}

	for path, tokens := range want {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		src := string(body)
		for _, token := range tokens {
			if !strings.Contains(src, token) {
				t.Fatalf("%s missing production caller %q", path, token)
			}
		}
	}
}
