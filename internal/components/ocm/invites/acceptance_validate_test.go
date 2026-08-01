// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

func TestValidateAcceptedIdentity(t *testing.T) {
	tests := []struct {
		name           string
		status         string
		userID         string
		normalizedHost string
		wantErr        error
	}{
		{name: "accepted with full identity", status: string(invites.InviteStatusAccepted), userID: "user", normalizedHost: "host.example"},
		{name: "accepted missing user id", status: string(invites.InviteStatusAccepted), normalizedHost: "host.example", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted missing normalized host", status: string(invites.InviteStatusAccepted), userID: "user", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted missing both", status: string(invites.InviteStatusAccepted), wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted whitespace-only identity", status: string(invites.InviteStatusAccepted), userID: " ", normalizedHost: "  ", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "pending without identity", status: string(invites.InviteStatusPending)},
		{name: "declined without identity", status: string(invites.InviteStatusDeclined)},
		{name: "non-accepted with identity is tolerated", status: string(invites.InviteStatusPending), userID: "user", normalizedHost: "host.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := invites.ValidateAcceptedIdentity(tt.status, tt.userID, tt.normalizedHost)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateAcceptedIdentity(%q, %q, %q) = %v, want %v",
					tt.status, tt.userID, tt.normalizedHost, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCreateInviteStatus(t *testing.T) {
	tests := []struct {
		name           string
		status         string
		userID         string
		normalizedHost string
		wantErr        error
	}{
		{name: "pending without identity", status: string(invites.InviteStatusPending)},
		{name: "pending with identity", status: string(invites.InviteStatusPending), userID: "user", normalizedHost: "host.example"},
		{name: "accepted with full identity", status: string(invites.InviteStatusAccepted), userID: "user", normalizedHost: "host.example"},
		{name: "accepted missing user id", status: string(invites.InviteStatusAccepted), normalizedHost: "host.example", wantErr: invites.ErrInvalidCreateStatus},
		{name: "accepted missing normalized host", status: string(invites.InviteStatusAccepted), userID: "user", wantErr: invites.ErrInvalidCreateStatus},
		{name: "accepted missing both", status: string(invites.InviteStatusAccepted), wantErr: invites.ErrInvalidCreateStatus},
		{name: "accepted whitespace-only identity", status: string(invites.InviteStatusAccepted), userID: " ", normalizedHost: "  ", wantErr: invites.ErrInvalidCreateStatus},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := invites.ValidateCreateInviteStatus(tt.status, tt.userID, tt.normalizedHost)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateCreateInviteStatus(%q, %q, %q) = %v, want %v",
					tt.status, tt.userID, tt.normalizedHost, err, tt.wantErr)
			}
		})
	}
}

func TestCoalesceAcceptedIdentity(t *testing.T) {
	tests := []struct {
		name        string
		argUserID   string
		argHost     string
		existUserID string
		existHost   string
		wantUserID  string
		wantHost    string
	}{
		{name: "arguments win over existing", argUserID: "new-user", argHost: "new.example", existUserID: "old-user", existHost: "old.example", wantUserID: "new-user", wantHost: "new.example"},
		{name: "empty arguments keep existing", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "old.example"},
		{name: "whitespace arguments keep existing", argUserID: " ", argHost: "  ", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "old.example"},
		{name: "whitespace-only user id coalesces to existing", argUserID: "\t ", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "old.example"},
		{name: "whitespace-only host coalesces to existing", argHost: " \t", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "old.example"},
		{name: "surrounded user id wins as-is", argUserID: "  new-user  ", existUserID: "old-user", existHost: "old.example", wantUserID: "  new-user  ", wantHost: "old.example"},
		{name: "surrounded host wins as-is", argHost: "  new.example  ", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "  new.example  "},
		{name: "user id coalesces independently", argHost: "new.example", existUserID: "old-user", existHost: "old.example", wantUserID: "old-user", wantHost: "new.example"},
		{name: "host coalesces independently", argUserID: "new-user", existUserID: "old-user", existHost: "old.example", wantUserID: "new-user", wantHost: "old.example"},
		{name: "both empty stays empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, host := invites.CoalesceAcceptedIdentity(tt.argUserID, tt.argHost, tt.existUserID, tt.existHost)
			if userID != tt.wantUserID || host != tt.wantHost {
				t.Errorf("CoalesceAcceptedIdentity(%q, %q, %q, %q) = (%q, %q), want (%q, %q)",
					tt.argUserID, tt.argHost, tt.existUserID, tt.existHost,
					userID, host, tt.wantUserID, tt.wantHost)
			}
		})
	}
}

func TestValidateUpdateAcceptedIdentity(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		argUserID   string
		argHost     string
		existUserID string
		existHost   string
		wantErr     error
	}{
		{name: "accepted update with full argument identity", status: string(invites.InviteStatusAccepted), argUserID: "user", argHost: "host.example"},
		{name: "accepted update keeps stored identity", status: string(invites.InviteStatusAccepted), existUserID: "user", existHost: "host.example"},
		{name: "accepted update coalesces whitespace-only arg to stored identity", status: string(invites.InviteStatusAccepted), argUserID: " ", argHost: "  ", existUserID: "user", existHost: "host.example"},
		{name: "accepted update mixes argument and stored identity", status: string(invites.InviteStatusAccepted), argUserID: "user", existHost: "host.example"},
		{name: "accepted update with no identity anywhere", status: string(invites.InviteStatusAccepted), wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted update missing user id everywhere", status: string(invites.InviteStatusAccepted), argHost: "host.example", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted update missing host everywhere", status: string(invites.InviteStatusAccepted), argUserID: "user", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "accepted update does not revive from whitespace", status: string(invites.InviteStatusAccepted), argUserID: " ", argHost: "  ", wantErr: invites.ErrInvalidAcceptedIdentity},
		{name: "pending update without identity", status: string(invites.InviteStatusPending)},
		{name: "declined update without identity", status: string(invites.InviteStatusDeclined)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := invites.ValidateUpdateAcceptedIdentity(tt.status, tt.argUserID, tt.argHost, tt.existUserID, tt.existHost)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateUpdateAcceptedIdentity(%q, %q, %q, %q, %q) = %v, want %v",
					tt.status, tt.argUserID, tt.argHost, tt.existUserID, tt.existHost, err, tt.wantErr)
			}
		})
	}
}
