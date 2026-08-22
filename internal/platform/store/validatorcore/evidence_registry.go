// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec/wire"

// Report-exchange endpoint identifiers. There is no tls endpoint: TLS is
// persisted only as a passive evidence_row.
const (
	EndpointDiscovery      = "discovery"
	EndpointJWKS           = "jwks"
	EndpointHTTPSig        = "httpsig-probe"
	EndpointShares         = "shares"
	EndpointInviteAccepted = "invite-accepted"
	EndpointNotifications  = wire.CapabilityNotifications
	EndpointOCMToken       = "ocm-token"
	EndpointWebDAV         = wire.ProtocolWebDAV
)

const (
	exchangeDirectionIn  = "in"
	exchangeDirectionOut = "out"
	exchangeActorPeer    = "peer"
	exchangeActorLocal   = "validator"

	requestIDActiveSharesIn          = "active-shares-in"
	requestIDActiveSharesOut         = "active-shares-out"
	requestIDActiveInviteAcceptedIn  = "active-invite-accepted-in"
	requestIDActiveInviteAcceptedOut = "active-invite-accepted-out"
	requestIDActiveNotificationsIn   = "active-notifications-in"
	requestIDActiveOCMExchange       = "active-ocm-code"
	requestIDActiveWebDAV            = "active-webdav"

	endpointPathShares         = "/ocm/shares"
	endpointPathInviteAccepted = "/ocm/invite-accepted"
	endpointPathNotifications  = "/ocm/notifications"
	endpointPathOCMToken       = "/ocm/token"
	endpointPathWebDAV         = "/webdav"
)

const (
	evidenceStepShareSent        = "share_sent"
	evidenceStepShareReceived    = "reverse_share"
	evidenceStepNotify           = "notify"
	evidenceStepTokenExchange    = "exchange"
	evidenceStepWebDAVGet        = "webdav_get"
	evidenceReasonForwardSent    = "forward_share_sent"
	evidenceReasonShareReceived  = "reverse_share_received"
	evidenceReasonOutgoingAccept = "outgoing_invite_accepted"
	evidenceReasonNotifyReceived = "notification_received"
	evidenceReasonTokenExchanged = "token_exchanged"
	evidenceReasonWebDAVObserved = "webdav_observed"
)

// AreaForEndpoint maps a persisted report-exchange endpoint to the
// specification area writers should use for a sibling evidence_row. The
// rater never consults this table; it scores EvidenceRow.Area only.
func AreaForEndpoint(endpointID string) (string, bool) {
	switch endpointID {
	case EndpointDiscovery:
		return SpecificationAreaDiscovery, true
	case EndpointJWKS:
		return SpecificationAreaJWKS, true
	case EndpointHTTPSig:
		return SpecificationAreaHTTPSig, true
	case EndpointShares, EndpointInviteAccepted:
		return SpecificationAreaSharing, true
	case EndpointNotifications:
		return SpecificationAreaNotification, true
	case EndpointOCMToken:
		return SpecificationAreaToken, true
	case EndpointWebDAV:
		return SpecificationAreaCapability, true
	default:
		return "", false
	}
}

// EndpointPath is the path-only URL stored on an active-leg transcript so
// the row never carries a host, query, token, or invite string.
func EndpointPath(endpointID string) string {
	switch endpointID {
	case EndpointShares:
		return endpointPathShares
	case EndpointInviteAccepted:
		return endpointPathInviteAccepted
	case EndpointNotifications:
		return endpointPathNotifications
	case EndpointOCMToken:
		return endpointPathOCMToken
	case EndpointWebDAV:
		return endpointPathWebDAV
	default:
		return ""
	}
}

func isKnownEvidenceArea(area string) bool {
	switch area {
	case SpecificationAreaDiscovery,
		SpecificationAreaTLS,
		SpecificationAreaJWKS,
		SpecificationAreaHTTPSig,
		SpecificationAreaSharing,
		SpecificationAreaNotification,
		SpecificationAreaToken,
		SpecificationAreaCapability:
		return true
	default:
		return false
	}
}

func mapEvidenceScoreArea(area string) (string, bool) {
	if !isKnownEvidenceArea(area) {
		return "", false
	}

	return area, true
}

func optionalExchangeID(id uint) *uint {
	if id == 0 {
		return nil
	}

	return &id
}

func cloneStringPtr(src *string) *string {
	if src == nil {
		return nil
	}

	copied := *src

	return &copied
}

// ProjectPublicEvidence copies only the allowlisted public evidence fields.
// Exchange IDs, URLs, headers, tokens, invite strings, and bodies are never
// copied even if a caller stuffed them onto the source row.
func ProjectPublicEvidence(items []SpecificationEvidence) []SpecificationEvidence {
	out := make([]SpecificationEvidence, 0, len(items))

	for _, item := range items {
		out = append(out, SpecificationEvidence{
			Source:          item.Source,
			Leg:             item.Leg,
			Area:            item.Area,
			ScoreArea:       item.ScoreArea,
			Step:            item.Step,
			ReasonCode:      item.ReasonCode,
			Severity:        item.Severity,
			Grade:           cloneStringPtr(item.Grade),
			AffectsGrade:    item.AffectsGrade,
			PayloadRedacted: item.PayloadRedacted,
			CreatedAt:       item.CreatedAt,
		})
	}

	return out
}
