// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func (h *Handler) executeOutgoingCreate(
	ctx context.Context,
	req sharesoutgoing.OutgoingShareRequest,
	user *identity.User,
	cleanPath, resourceType, name string,
	plan *DispatchPlan,
) (*sharesoutgoing.OutgoingShare, error) {
	delivered := false

	if plan != nil {
		defer func() {
			if delivered {
				return
			}

			releaseCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), dispatchReleaseTimeout)
			defer stop()

			if err := h.dispatchHook.AbortSend(releaseCtx, plan); err != nil {
				h.logger.Error("failed to release dispatch permit", "test_run_id", plan.TestRunID, "error", err)
			}
		}()
	}

	providerID, webdavID, sharedSecret, err := shareIdentifiers(plan)
	if err != nil {
		return nil, err
	}

	origin, disc, requirements, err := h.lookupReceiver(ctx, req)
	if err != nil {
		return nil, err
	}

	webdavURI, err := h.planWebDAVURI(ctx, req, plan, webdavID, disc)
	if err != nil {
		return nil, err
	}

	owner := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:       providerID.String(),
		WebDAVID:         webdavID.String(),
		SharedSecret:     sharedSecret,
		LocalPath:        cleanPath,
		ReceiverHost:     origin.peerDomain,
		ReceiverEndPoint: disc.EndPoint,
		ShareWith:        req.ShareWith,
		Name:             name,
		ResourceType:     resourceType,
		ShareType:        "user",
		Permissions:      req.Permissions,
		Owner:            owner,
		Sender:           sender,
		Status:           ocmshares.OutgoingShareStatusPending,
		Requirements:     requirements,
	}

	stored, err := h.storeOutgoingShare(ctx, share, plan)
	if err != nil {
		return nil, err
	}

	share = stored
	payload := outgoingSharePayload(share, webdavURI)

	if err := h.postOutgoingShare(ctx, req, origin, disc, share, payload, plan); err != nil {
		return nil, err
	}

	delivered = true

	if plan != nil {
		commitCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), dispatchReleaseTimeout)
		defer stop()

		if err := h.dispatchHook.CommitSent(commitCtx, plan, share); err != nil {
			return nil, fmt.Errorf("outgoing share commit: %w", err)
		}
	}

	share.Status = ocmshares.OutgoingShareStatusSent
	share.Error = ""
	sentAt := time.Now()
	share.SentAt = &sentAt

	if err := h.repo.Update(ctx, share); err != nil {
		return nil, fmt.Errorf("outgoing share local persist: %w", err)
	}

	return share, nil
}

func shareIdentifiers(plan *DispatchPlan) (uuid.UUID, uuid.UUID, string, error) {
	if plan == nil {
		return mintShareIDs()
	}

	providerID, err := uuid.Parse(plan.ProviderID)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, "", fmt.Errorf("outgoing share planned provider id: %w", err)
	}

	webdavID, err := uuid.Parse(plan.WebDAVID)
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, "", fmt.Errorf("outgoing share planned webdav id: %w", err)
	}

	return providerID, webdavID, plan.SharedSecret, nil
}

func mintShareIDs() (uuid.UUID, uuid.UUID, string, error) {
	providerID, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, "", fmt.Errorf("outgoing share provider id: %w", err)
	}

	webdavID, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, "", fmt.Errorf("outgoing share webdav id: %w", err)
	}

	sharedSecret, err := generateSharedSecret()
	if err != nil {
		return uuid.UUID{}, uuid.UUID{}, "", fmt.Errorf("outgoing share shared secret: %w", err)
	}

	return providerID, webdavID, sharedSecret, nil
}

func (h *Handler) lookupReceiver(
	ctx context.Context,
	req sharesoutgoing.OutgoingShareRequest,
) (resolvedPeerOrigin, *spec.Discovery, []string, error) {
	origin := h.resolvePeerOrigin(req.ReceiverDomain)
	if origin.baseURL == "" || origin.peerDomain == "" {
		return resolvedPeerOrigin{}, nil, nil, errors.New("outgoing share: could not resolve receiver origin")
	}

	disc, err := h.discoveryClient.Discover(ctx, origin.baseURL)
	if err != nil {
		return resolvedPeerOrigin{}, nil, nil, fmt.Errorf("outgoing share discover receiver: %w", err)
	}

	facts := policy.Facts{}
	if h.resolver != nil {
		facts = h.resolver.ResolveFacts(origin.peerDomain)
	}

	mustInclude := mustIncludeTokenExchange(facts, disc)
	requirements := tokenExchangeRequirements(mustInclude)

	if mustInclude && h.localTokenEndPoint == "" {
		return resolvedPeerOrigin{}, nil, nil, errors.New("outgoing share: local sender is not configured for token exchange")
	}

	if mustInclude && !disc.SupportsTokenExchange() {
		return resolvedPeerOrigin{}, nil, nil, errors.New("outgoing share: receiver does not advertise exchange-token")
	}

	return origin, disc, requirements, nil
}

func (h *Handler) planWebDAVURI(
	ctx context.Context,
	req sharesoutgoing.OutgoingShareRequest,
	plan *DispatchPlan,
	webdavID uuid.UUID,
	disc *spec.Discovery,
) (string, error) {
	if plan != nil && plan.WebDAVURI != "" {
		return plan.WebDAVURI, nil
	}

	webdavURI, err := h.computeWebDAVURI(req, webdavID, disc)
	if err != nil {
		return "", err
	}

	if plan == nil {
		return webdavURI, nil
	}

	if err := h.dispatchHook.NoteWireURI(ctx, plan, webdavURI); err != nil {
		return "", fmt.Errorf("outgoing share snapshot wire uri: %w", err)
	}

	plan.WebDAVURI = webdavURI

	return webdavURI, nil
}

func (h *Handler) computeWebDAVURI(
	req sharesoutgoing.OutgoingShareRequest,
	webdavID uuid.UUID,
	disc *spec.Discovery,
) (string, error) {
	webdavURI := webdavID.String()
	if disc.WebDAVReceiveURIKind() != spec.WebDAVReceiveURIAbsolute {
		return webdavURI, nil
	}

	absURI, err := disc.BuildWebDAVURL(webdavID.String())
	if err != nil {
		return "", fmt.Errorf("outgoing share absolute webdav uri: %w", err)
	}

	if h.peerOrigin == nil || !h.peerOrigin.IsAbsoluteURIAllowed(absURI, req.ReceiverDomain) {
		return "", errors.New("outgoing share: receiver webdav-receive absolute uri failed authority check")
	}

	return absURI, nil
}

func (h *Handler) storeOutgoingShare(
	ctx context.Context,
	share *sharesoutgoing.OutgoingShare,
	plan *DispatchPlan,
) (*sharesoutgoing.OutgoingShare, error) {
	if plan == nil {
		if err := h.repo.Create(ctx, share); err != nil {
			return nil, fmt.Errorf("outgoing share persist: %w", err)
		}

		return share, nil
	}

	if err := h.repo.Create(ctx, share); err == nil {
		return share, nil
	}

	existing, err := h.repo.GetByProviderID(ctx, share.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("outgoing share persist planned: %w", err)
	}

	return existing, nil
}

func (h *Handler) postOutgoingShare(
	ctx context.Context,
	_ sharesoutgoing.OutgoingShareRequest,
	origin resolvedPeerOrigin,
	disc *spec.Discovery,
	share *sharesoutgoing.OutgoingShare,
	payload spec.NewShareRequest,
	plan *DispatchPlan,
) error {
	if plan != nil {
		if err := h.dispatchHook.CheckSendClaim(ctx, plan); err != nil {
			return fmt.Errorf("outgoing share send claim: %w", err)
		}
	}

	if err := h.sendShareToReceiver(ctx, origin, disc, payload); err != nil {
		share.Status = ocmshares.OutgoingShareStatusFailed
		share.Error = err.Error()

		if uerr := h.repo.Update(ctx, share); uerr != nil {
			h.logger.Error("failed to mark outgoing share as failed", "share_id", share.ShareID, "error", uerr)
		}

		return fmt.Errorf("outgoing share deliver: %w", err)
	}

	return nil
}
