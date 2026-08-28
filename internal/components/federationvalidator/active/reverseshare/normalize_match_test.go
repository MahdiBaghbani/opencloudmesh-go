// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// The observer lookup and the inbox scan both match the share's sender host
// against the run target in scheme-aware normalized authority form: default
// ports for the local scheme fold away, every non-default port stays
// significant, and a stored host that fails normalization fails closed.
var normalizedSenderCases = []struct {
	name       string
	scheme     string
	senderHost string
	wantMatch  bool
}{
	{
		name:       "default port and case fold to target",
		scheme:     "https",
		senderHost: "Peer.Example:443",
		wantMatch:  true,
	},
	{
		name:       "non-default port never matches",
		scheme:     "https",
		senderHost: "peer.example:8443",
		wantMatch:  false,
	},
	{
		name:       "http default port is not https default",
		scheme:     "https",
		senderHost: "peer.example:80",
		wantMatch:  false,
	},
	{
		name:       "http default port matches under http scheme",
		scheme:     "http",
		senderHost: "Peer.Example:80",
		wantMatch:  true,
	},
	{
		name:       "https default port is not http default",
		scheme:     "http",
		senderHost: "peer.example:443",
		wantMatch:  false,
	},
	{
		name:       "authority carrying a scheme fails closed",
		scheme:     "https",
		senderHost: "https://peer.example",
		wantMatch:  false,
	},
}

// newServiceWithScheme rebuilds the service on the env's store and inbox with
// a different local scheme, for scheme-variant normalization cases.
func newServiceWithScheme(t *testing.T, env *testEnv, scheme string) *reverseshare.Service {
	t.Helper()

	svc, err := reverseshare.New(reverseshare.Deps{
		Store:          env.store,
		IncomingShares: env.shares,
		LocalIdentity:  localidentity.Identity{Scheme: scheme},
	})
	if err != nil {
		t.Fatalf("reverseshare.New: %v", err)
	}

	return svc
}

func TestObserveCreatedShare_NormalizedSenderHostMatching(t *testing.T) {
	t.Parallel()

	for _, tt := range normalizedSenderCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t)
			svc := newServiceWithScheme(t, env, tt.scheme)

			bobID := env.seedRun(t, "run-observe-normalized", validatorcore.StateReverseAwaitingShare)
			share := env.addShare(t, bobID, "provider-normalized", tt.senderHost)

			if err := svc.ObserveCreatedShare(t.Context(), share); err != nil {
				t.Fatalf("ObserveCreatedShare: %v", err)
			}

			run := env.requireRun(t, "run-observe-normalized")

			if !tt.wantMatch {
				if run.State != validatorcore.StateReverseAwaitingShare {
					t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateReverseAwaitingShare)
				}

				if run.ReverseShareProviderID != nil {
					t.Fatalf("reverse_share_provider_id = %v, want nil", run.ReverseShareProviderID)
				}

				return
			}

			if run.State != validatorcore.StateTerminalPass {
				t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalPass)
			}

			if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != "provider-normalized" {
				t.Fatalf("reverse_share_provider_id = %v, want %q",
					run.ReverseShareProviderID, "provider-normalized")
			}
		})
	}
}

func TestOpenReverseShareWait_NormalizedSenderHostMatching(t *testing.T) {
	t.Parallel()

	for _, tt := range normalizedSenderCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t)
			svc := newServiceWithScheme(t, env, tt.scheme)

			bobID := env.seedRun(t, "run-open-normalized", validatorcore.StateCapabilityExercise)
			env.addShare(t, bobID, "provider-normalized", tt.senderHost)

			if err := svc.OpenReverseShareWait(t.Context(), "run-open-normalized"); err != nil {
				t.Fatalf("OpenReverseShareWait: %v", err)
			}

			run := env.requireRun(t, "run-open-normalized")

			if !tt.wantMatch {
				if run.State != validatorcore.StateReverseAwaitingShare {
					t.Fatalf("state = %q, want %q (non-matching sender opens the wait)",
						run.State, validatorcore.StateReverseAwaitingShare)
				}

				if run.ReverseShareProviderID != nil {
					t.Fatalf("reverse_share_provider_id = %v, want nil", run.ReverseShareProviderID)
				}

				return
			}

			if run.State != validatorcore.StateTerminalPass {
				t.Fatalf("state = %q, want %q (early share passes instead of opening the wait)",
					run.State, validatorcore.StateTerminalPass)
			}

			if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != "provider-normalized" {
				t.Fatalf("reverse_share_provider_id = %v, want %q",
					run.ReverseShareProviderID, "provider-normalized")
			}
		})
	}
}
