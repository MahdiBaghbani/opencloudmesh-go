// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Handler serves POST /ocm/shares with recipient resolution and peer-trust gating.
type Handler struct {
	repo                        IncomingShareRepo
	partyRepo                   identity.PartyRepo
	policyEngine                *peertrust.PolicyEngine
	resolver                    *policy.PeerMappingResolver
	incomingInviteRepo          invitesincoming.IncomingInviteRepo
	outgoingInviteRepo          invitesoutgoing.OutgoingInviteRepo
	mustInviteEnforced          bool
	localProviderFQDNForCompare string
	localScheme                 string
}

func NewHandler( //nolint:revive // exported: trivial constructor wiring the handler dependencies
	repo IncomingShareRepo,
	partyRepo identity.PartyRepo,
	policyEngine *peertrust.PolicyEngine,
	incomingInviteRepo invitesincoming.IncomingInviteRepo,
	outgoingInviteRepo invitesoutgoing.OutgoingInviteRepo,
	mustInviteEnforced bool,
	localProviderFQDNForCompare string,
	localScheme string,
	resolver *policy.PeerMappingResolver,
) *Handler {
	return &Handler{
		repo:                        repo,
		partyRepo:                   partyRepo,
		policyEngine:                policyEngine,
		resolver:                    resolver,
		incomingInviteRepo:          incomingInviteRepo,
		outgoingInviteRepo:          outgoingInviteRepo,
		mustInviteEnforced:          mustInviteEnforced,
		localProviderFQDNForCompare: localProviderFQDNForCompare,
		localScheme:                 localScheme,
	}
}

// CreateShare handles POST /ocm/shares: parses, resolves the recipient, and persists the incoming share.
func (h *Handler) CreateShare(w http.ResponseWriter, r *http.Request) {
	req, rawFields, ok := h.parseCreateShareRequest(w, r)
	if !ok {
		return
	}

	localRequires := true

	if h.resolver != nil {
		if _, senderHost, err := address.Parse(req.Sender); err == nil {
			localRequires = h.resolver.ResolveFacts(senderHost).RequiresTokenExchange
		}
	}

	if !h.validateProtocolAdmissions(w, r, &req, rawFields, localRequires) {
		return
	}

	resolvedUser, ok := h.resolveShareRecipient(w, r, &req)
	if !ok {
		return
	}

	senderHost, ownerHost, ok := h.authenticateSenderAndResolveOwner(w, r, &req)
	if !ok {
		return
	}

	if !h.gateMustInvite(w, r, &req, resolvedUser) {
		return
	}

	h.storeIncomingShare(w, r, &req, senderHost, ownerHost, resolvedUser)
}

func dedupeValidationErrors(errs []spec.ValidationError) []spec.ValidationError {
	if len(errs) == 0 {
		return errs
	}

	seen := make(map[string]struct{}, len(errs))

	out := make([]spec.ValidationError, 0, len(errs))
	for _, e := range errs {
		key := e.Name + "\x00" + e.Message
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, e)
	}

	return out
}

// writeProtocolValidationErrors maps spec protocol validation errors to the
// shared OCM response taxonomy used by both the webdav and webapp arms: any
// UNSUPPORTED value yields PROTOCOL_NOT_SUPPORTED (501); all other errors
// (missing/invalid required fields, including must-use-mfa hard-rejects) yield
// INVALID_PROTOCOL
// (400) with the validation errors attached so the rejection is observable.
func writeProtocolValidationErrors(w http.ResponseWriter, errs []spec.ValidationError) {
	for _, e := range errs {
		if e.Message == "UNSUPPORTED" {
			spec.WriteProtocolNotSupported(w)
			return
		}
	}

	spec.WriteValidationError(w, "INVALID_PROTOCOL", errs)
}

// resolveRecipient: canonical ID -> username -> email -> federated opaque ID (if no @, base64-like, idp matches).
func (h *Handler) resolveRecipient(ctx context.Context, identifier string) (*identity.User, error) {
	user, err := h.partyRepo.Get(ctx, identifier)
	if err == nil {
		return user, nil
	}

	user, err = h.partyRepo.GetByUsername(ctx, identifier)
	if err == nil {
		return user, nil
	}

	user, err = h.partyRepo.GetByEmail(ctx, identifier)
	if err == nil {
		return user, nil
	}

	if !strings.Contains(identifier, "@") && address.LooksLikeBase64(identifier) {
		decodedUserID, decodedIDP, ok := address.DecodeFederatedOpaqueID(identifier)
		if ok {
			normalizedIDP, normErr := hostport.Normalize(decodedIDP, h.localScheme)
			if normErr == nil && strings.EqualFold(normalizedIDP, h.localProviderFQDNForCompare) {
				user, err := h.partyRepo.Get(ctx, decodedUserID)
				if err == nil {
					return user, nil
				}
			}
		}
	}

	return nil, errors.New("recipient not found")
}
