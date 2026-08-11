// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestValidateNotificationRequest_RequiredFields(t *testing.T) {
	t.Parallel()

	errs := spec.ValidateNotificationRequest(&spec.NotificationRequest{})
	if len(errs) != 2 {
		t.Fatalf("expected 2 validation errors, got %d", len(errs))
	}
}

func TestValidateNotificationRequest_UnsupportedType(t *testing.T) {
	t.Parallel()

	errs := spec.ValidateNotificationRequest(&spec.NotificationRequest{
		NotificationType: "UNKNOWN",
		ProviderID:       "provider-1",
	})
	if len(errs) != 1 || errs[0].Message != "UNSUPPORTED" {
		t.Fatalf("expected unsupported notificationType, got %#v", errs)
	}
}

func TestValidateNotificationRequest_ExperimentalTypes(t *testing.T) {
	t.Parallel()

	for _, typ := range []string{"REQUEST_RESHARE", "RESHARE_UNDO", "RESHARE_CHANGE_PERMISSION"} {
		errs := spec.ValidateNotificationRequest(&spec.NotificationRequest{
			NotificationType: typ,
			ProviderID:       "provider-1",
		})
		if len(errs) != 1 || errs[0].Message != "UNSUPPORTED" {
			t.Fatalf("type %q: expected unsupported, got %#v", typ, errs)
		}
	}
}

func TestValidateNotificationRequest_SupportedTypes(t *testing.T) {
	t.Parallel()

	for _, typ := range spec.SupportedNotificationTypes {
		errs := spec.ValidateNotificationRequest(&spec.NotificationRequest{
			NotificationType: typ,
			ProviderID:       "provider-1",
		})
		if len(errs) != 0 {
			t.Fatalf("type %q: expected no errors, got %#v", typ, errs)
		}
	}
}

func TestSupportedNotificationTypes_ContainsCoreTypes(t *testing.T) {
	t.Parallel()

	want := map[string]struct{}{
		spec.NotificationTypeShareAccepted: {},
		spec.NotificationTypeShareDeclined: {},
		spec.NotificationTypeShareUnshared: {},
	}

	for _, typ := range spec.SupportedNotificationTypes {
		delete(want, typ)
	}

	if len(want) != 0 {
		t.Fatalf("SupportedNotificationTypes missing entries: %#v", want)
	}
}
