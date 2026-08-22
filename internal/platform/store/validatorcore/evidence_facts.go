// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "net/http"

// ReverseShareReceivedFact is the reverse-leg sharing observation recorded
// when the peer's reverse share reaches Bob.
func ReverseShareReceivedFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepShareReceived,
		ReasonCode:   evidenceReasonShareReceived,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegReverse,
		ExchangeID:   exchangeID,
	}
}

// ForwardShareSentFact is the forward-leg sharing observation recorded after
// the designated outgoing share is delivered.
func ForwardShareSentFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepShareSent,
		ReasonCode:   evidenceReasonForwardSent,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegForward,
		ExchangeID:   exchangeID,
	}
}

// OutgoingInviteAcceptedFact is the forward-leg sharing observation recorded
// when the peer accepts the session's outgoing invite.
func OutgoingInviteAcceptedFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonOutgoingAccept,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegForward,
		ExchangeID:   exchangeID,
	}
}

// ReverseInviteAcceptedFact is the reverse-leg sharing observation recorded
// when the validator accepts the incoming reverse invite and notifies the
// sender on the outbound invite-accepted exchange.
func ReverseInviteAcceptedFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonReverseAccepted,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegReverse,
		ExchangeID:   exchangeID,
	}
}

// NotificationReceivedFact is the explicit notification-area writer.
func NotificationReceivedFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaNotification,
		Step:         evidenceStepNotify,
		ReasonCode:   evidenceReasonNotifyReceived,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegForward,
		ExchangeID:   exchangeID,
	}
}

// TokenExchangedFact is the explicit token-area writer.
func TokenExchangedFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaToken,
		Step:         evidenceStepTokenExchange,
		ReasonCode:   evidenceReasonTokenExchanged,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegForward,
		ExchangeID:   exchangeID,
	}
}

// WebDAVTranscriptFact is the WebDAV sibling: it links the transcript but
// does not grade. Capability scoring comes from other evidence rows.
func WebDAVTranscriptFact(testRunID string, exchangeID *uint) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaCapability,
		Step:         evidenceStepWebDAVGet,
		ReasonCode:   evidenceReasonWebDAVObserved,
		Severity:     GradePass,
		AffectsGrade: false,
		Leg:          evidenceLegForward,
		ExchangeID:   exchangeID,
	}
}

func activeExchangeDraft(
	testRunID, endpointID, method, direction, requestID, leg, actor string,
	statusCode int,
) ActiveExchangeDraft {
	return ActiveExchangeDraft{
		TestRunID:  testRunID,
		EndpointID: endpointID,
		Method:     method,
		URL:        EndpointPath(endpointID),
		Direction:  direction,
		RequestID:  requestID,
		StatusCode: statusCode,
		Leg:        leg,
		Actor:      actor,
	}
}

// IncomingSharesExchange is the inbound POST /ocm/shares transcript draft.
func IncomingSharesExchange(testRunID string) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointShares,
		http.MethodPost,
		exchangeDirectionIn,
		requestIDActiveSharesIn,
		evidenceLegReverse,
		exchangeActorPeer,
		http.StatusCreated,
	)
}

// OutgoingSharesExchange is the outbound POST /ocm/shares transcript draft.
func OutgoingSharesExchange(testRunID string) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointShares,
		http.MethodPost,
		exchangeDirectionOut,
		requestIDActiveSharesOut,
		evidenceLegForward,
		exchangeActorLocal,
		http.StatusCreated,
	)
}

// IncomingInviteAcceptedExchange is the inbound invite-accepted transcript.
func IncomingInviteAcceptedExchange(testRunID string, statusCode int) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointInviteAccepted,
		http.MethodPost,
		exchangeDirectionIn,
		requestIDActiveInviteAcceptedIn,
		evidenceLegForward,
		exchangeActorPeer,
		statusCode,
	)
}

// OutgoingInviteAcceptedExchange is the outbound invite-accepted transcript.
func OutgoingInviteAcceptedExchange(testRunID string, statusCode int) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointInviteAccepted,
		http.MethodPost,
		exchangeDirectionOut,
		requestIDActiveInviteAcceptedOut,
		evidenceLegReverse,
		exchangeActorLocal,
		statusCode,
	)
}

// IncomingNotificationExchange is the inbound notifications transcript.
func IncomingNotificationExchange(testRunID string) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointNotifications,
		http.MethodPost,
		exchangeDirectionIn,
		requestIDActiveNotificationsIn,
		evidenceLegForward,
		exchangeActorPeer,
		http.StatusOK,
	)
}

// IncomingTokenExchange is the inbound ocm-token transcript.
func IncomingTokenExchange(testRunID string) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointOCMToken,
		http.MethodPost,
		exchangeDirectionIn,
		requestIDActiveOCMExchange,
		evidenceLegForward,
		exchangeActorPeer,
		http.StatusOK,
	)
}

// IncomingWebDAVExchange is the inbound WebDAV GET transcript.
func IncomingWebDAVExchange(testRunID string) ActiveExchangeDraft {
	return activeExchangeDraft(
		testRunID,
		EndpointWebDAV,
		http.MethodGet,
		exchangeDirectionIn,
		requestIDActiveWebDAV,
		evidenceLegForward,
		exchangeActorPeer,
		http.StatusOK,
	)
}
