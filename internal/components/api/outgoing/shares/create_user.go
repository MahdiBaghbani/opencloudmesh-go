// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

var (
	errOutgoingUserRequired    = errors.New("outgoing share user is required")
	errOutgoingRequestInvalid  = errors.New("outgoing share request is invalid")
	errOutgoingResourceInvalid = errors.New("outgoing share local resource is invalid")
)

// CreateAsUser creates and delivers an outgoing share for the supplied user
// without an HTTP session. GuardCreate still runs when a dispatch hook is
// installed. Ordinary HandleCreate behavior is unchanged.
func (h *Handler) CreateAsUser(
	ctx context.Context,
	user *identity.User,
	req sharesoutgoing.OutgoingShareRequest,
) (*sharesoutgoing.OutgoingShare, error) {
	if h == nil {
		return nil, errors.New("outgoing share handler is not configured")
	}

	if user == nil || user.ID == "" {
		return nil, errOutgoingUserRequired
	}

	if err := validateOutgoingShareRequest(req); err != nil {
		return nil, err
	}

	cleanPath, resourceType, name, err := h.lookupLocalResource(req)
	if err != nil {
		return nil, err
	}

	plan, err := h.applyDispatchGuard(ctx, req, user.ID)
	if err != nil {
		return nil, err
	}

	if plan != nil && plan.ReplayShare != nil {
		return plan.ReplayShare, nil
	}

	return h.executeOutgoingCreate(ctx, req, user, cleanPath, resourceType, name, plan)
}

func validateOutgoingShareRequest(req sharesoutgoing.OutgoingShareRequest) error {
	if req.ReceiverDomain == "" {
		return fmt.Errorf("%w: receiverDomain is required", errOutgoingRequestInvalid)
	}

	if req.ShareWith == "" {
		return fmt.Errorf("%w: shareWith is required", errOutgoingRequestInvalid)
	}

	if req.LocalPath == "" {
		return fmt.Errorf("%w: localPath is required", errOutgoingRequestInvalid)
	}

	if len(req.Permissions) == 0 {
		return fmt.Errorf("%w: permissions is required", errOutgoingRequestInvalid)
	}

	for _, perm := range req.Permissions {
		if !slices.Contains(spec.SupportedWebDAVPermissions, perm) {
			return fmt.Errorf("%w: permissions must be read-only", errOutgoingRequestInvalid)
		}
	}

	return nil
}

func (h *Handler) lookupLocalResource(req sharesoutgoing.OutgoingShareRequest) (string, string, string, error) {
	cleanPath, err := h.validateLocalPath(req.LocalPath)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %s", errOutgoingResourceInvalid, err.Error())
	}

	stat, err := os.Stat(cleanPath)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: file does not exist", errOutgoingResourceInvalid)
	}

	if stat.IsDir() {
		return "", "", "", fmt.Errorf("%w: directory shares are not supported; only single files", errOutgoingResourceInvalid)
	}

	resourceType := req.ResourceType
	if resourceType == "" {
		resourceType = "file"
	} else if resourceType != spec.SupportedResourceTypes[0] {
		return "", "", "", fmt.Errorf(
			"%w: resource type %q is not supported; only %q is supported",
			errOutgoingResourceInvalid,
			resourceType,
			spec.SupportedResourceTypes[0],
		)
	}

	name := req.Name
	if name == "" {
		name = filepath.Base(cleanPath)
	}

	return cleanPath, resourceType, name, nil
}

func (h *Handler) applyDispatchGuard(
	ctx context.Context,
	req sharesoutgoing.OutgoingShareRequest,
	userID string,
) (*DispatchPlan, error) {
	if h.dispatchHook == nil {
		return nil, nil //nolint:nilnil // intentional: (nil, nil) keeps the generic unguarded flow
	}

	plan, err := h.dispatchHook.GuardCreate(ctx, req, userID)
	if err != nil {
		return nil, fmt.Errorf("outgoing share guard: %w", err)
	}

	return plan, nil
}
