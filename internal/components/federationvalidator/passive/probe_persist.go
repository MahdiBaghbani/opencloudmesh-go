// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/httpsigprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	evidenceStepFetch        = "fetch"
	evidenceStepHandshake    = "handshake"
	evidenceStepProbe        = "probe"
	reasonDiscoveryProbed    = "discovery_probed"
	reasonTLSProbed          = "tls_probed"
	reasonJWKSProbed         = "jwks_probed"
	reasonJWKSUnadvertised   = "jwks_unadvertised"
	reasonHTTPSigProbed      = "httpsig_probed"
	exchangeDiscoveryID      = "discovery"
	exchangeJWKSID           = "jwks"
	requestIDDiscovery       = "passive-discovery"
	requestIDJWKS            = "passive-jwks"
	requestIDHTTPSig         = "passive-httpsig-probe"
	requestIDHTTPSigTampered = "passive-httpsig-tampered"
)

func (p *ProbeRunner) persistProbeBundle(ctx context.Context, testRunID string, bundle probeBundle) error {
	discoveryID, err := p.persistDiscoveryExchange(ctx, testRunID, bundle)
	if err != nil {
		return err
	}

	if persistErr := p.persistAreaFact(ctx, testRunID, discoveryFact(bundle, optionalExchangeID(discoveryID))); persistErr != nil {
		return persistErr
	}

	if persistErr := p.persistTLSFact(ctx, testRunID, bundle); persistErr != nil {
		return persistErr
	}

	jwksID, err := p.persistJWKSExchange(ctx, testRunID, bundle)
	if err != nil {
		return err
	}

	if persistErr := p.persistAreaFact(ctx, testRunID, jwksFact(bundle, optionalExchangeID(jwksID))); persistErr != nil {
		return persistErr
	}

	httpsigID, err := p.persistHTTPSigExchange(ctx, testRunID, bundle)
	if err != nil {
		return err
	}

	if persistErr := p.persistAreaFact(ctx, testRunID, httpsigFact(bundle, optionalExchangeID(httpsigID))); persistErr != nil {
		return persistErr
	}

	if stampErr := p.store.StampPassiveProbeMetadata(
		ctx,
		testRunID,
		bundle.jwksURI,
		bundle.platform,
		bundle.apiVersion,
	); stampErr != nil {
		return fmt.Errorf("passive probe stamp metadata: %w", stampErr)
	}

	return nil
}

func (p *ProbeRunner) persistDiscoveryExchange(
	ctx context.Context,
	testRunID string,
	bundle probeBundle,
) (uint, error) {
	row := baseExchange(testRunID, exchangeDiscoveryID, attemptRequestID(requestIDDiscovery, bundle.attempt))
	row.Method = http.MethodGet
	row.URL = bundle.discoveryURL
	applyFetchTranscript(row, bundle)

	return p.insertExchange(ctx, row)
}

func (p *ProbeRunner) persistJWKSExchange(
	ctx context.Context,
	testRunID string,
	bundle probeBundle,
) (uint, error) {
	if !bundle.jwksAdvertised || bundle.jwks.URI == "" {
		return 0, nil
	}

	row := baseExchange(testRunID, exchangeJWKSID, attemptRequestID(requestIDJWKS, bundle.attempt))
	row.Method = bundle.jwks.Method
	row.URL = bundle.jwks.URI
	applyBodyAndHeaders(row, nil, bundle.jwks.Headers, nil, bundle.jwks.Body, bundle.jwks.Err)
	applyStatus(row, bundle.jwks.Status)

	return p.insertExchange(ctx, row)
}

func (p *ProbeRunner) persistHTTPSigExchange(
	ctx context.Context,
	testRunID string,
	bundle probeBundle,
) (uint, error) {
	if !shouldPersistHTTPSig(bundle.httpsig) {
		return 0, nil
	}

	persistLeg := func(leg httpsigprobe.Exchange, requestID string) (uint, error) {
		if !shouldPersistHTTPSigLeg(leg) {
			return 0, nil
		}

		row := baseExchange(testRunID, httpsigprobe.EndpointID, requestID)
		row.Method = firstNonEmpty(leg.Method, http.MethodGet)
		row.URL = firstNonEmpty(leg.URL, bundle.httpsig.ProbeURL)
		applyBodyAndHeaders(row, leg.ReqHeaders, leg.Headers, nil, leg.Body, leg.Err)
		applyStatus(row, leg.Status)
		applySignature(row, leg.SigRaw)

		return p.insertExchange(ctx, row)
	}

	validID, err := persistLeg(
		bundle.httpsig.Valid,
		attemptRequestID(requestIDHTTPSig, bundle.attempt),
	)
	if err != nil {
		return 0, err
	}

	tamperedID, err := persistLeg(
		bundle.httpsig.Tampered,
		attemptRequestID(requestIDHTTPSigTampered, bundle.attempt),
	)
	if err != nil {
		return 0, err
	}

	if validID != 0 {
		return validID, nil
	}

	return tamperedID, nil
}

func (p *ProbeRunner) persistTLSFact(ctx context.Context, testRunID string, bundle probeBundle) error {
	if bundle.grades.tls == nil || *bundle.grades.tls == "" {
		return nil
	}

	return p.persistAreaFact(ctx, testRunID, validatorcore.ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         validatorcore.SpecificationAreaTLS,
		Step:         evidenceStepHandshake,
		ReasonCode:   reasonTLSProbed,
		Severity:     *bundle.grades.tls,
		AffectsGrade: true,
		Leg:          validatorcore.EvidenceLegPassive,
	})
}

func (p *ProbeRunner) persistAreaFact(
	ctx context.Context,
	testRunID string,
	in validatorcore.ApplyEvidenceFactInput,
) error {
	in.TestRunID = testRunID
	if in.Leg == "" {
		in.Leg = validatorcore.EvidenceLegPassive
	}

	if err := p.store.ReplaceEvidenceFact(ctx, in); err != nil {
		return fmt.Errorf("passive probe persist %s fact: %w", in.Area, err)
	}

	return nil
}

func discoveryFact(bundle probeBundle, exchangeID *uint) validatorcore.ApplyEvidenceFactInput {
	return validatorcore.ApplyEvidenceFactInput{
		Area:            validatorcore.SpecificationAreaDiscovery,
		Step:            evidenceStepFetch,
		ReasonCode:      reasonDiscoveryProbed,
		ExchangeID:      exchangeID,
		Severity:        gradeOrFail(bundle.grades.discovery),
		AffectsGrade:    true,
		PayloadRedacted: compactPayload(bundle.grades.discovery, bundle.fetchErr),
		Leg:             validatorcore.EvidenceLegPassive,
	}
}

func jwksFact(bundle probeBundle, exchangeID *uint) validatorcore.ApplyEvidenceFactInput {
	reason := reasonJWKSProbed
	if !bundle.jwksAdvertised {
		reason = reasonJWKSUnadvertised
	}

	return validatorcore.ApplyEvidenceFactInput{
		Area:            validatorcore.SpecificationAreaJWKS,
		Step:            evidenceStepFetch,
		ReasonCode:      reason,
		ExchangeID:      exchangeID,
		Severity:        firstNonEmpty(bundle.jwks.Grade, validatorcore.GradeFail),
		AffectsGrade:    true,
		PayloadRedacted: compactPayload(bundle.grades.jwks, bundle.jwks.Err),
		Leg:             validatorcore.EvidenceLegPassive,
	}
}

func httpsigFact(bundle probeBundle, exchangeID *uint) validatorcore.ApplyEvidenceFactInput {
	return validatorcore.ApplyEvidenceFactInput{
		Area:            validatorcore.SpecificationAreaHTTPSig,
		Step:            evidenceStepProbe,
		ReasonCode:      reasonHTTPSigProbed,
		ExchangeID:      exchangeID,
		Severity:        firstNonEmpty(bundle.httpsig.Grade, validatorcore.GradeFail),
		AffectsGrade:    true,
		PayloadRedacted: httpsigPayload(bundle.httpsig),
		Leg:             validatorcore.EvidenceLegPassive,
	}
}

func compactPayload(grade *string, err error) string {
	var b strings.Builder

	writeString(&b, `{"grade":`)
	writeString(&b, strconv.Quote(gradeOrFail(grade)))

	if err != nil {
		writeString(&b, `,"error":`)
		writeString(&b, strconv.Quote(err.Error()))
	}

	writeByte(&b, '}')

	return b.String()
}

func httpsigPayload(result httpsigprobe.Result) string {
	signed := result.Valid.SigRaw != "" && result.Tampered.SigRaw != ""

	var b strings.Builder

	writeString(&b, `{"endpoint_id":`)
	writeString(&b, strconv.Quote(httpsigprobe.EndpointID))
	writeString(&b, `,"grade":`)
	writeString(&b, strconv.Quote(result.Grade))
	writeString(&b, `,"reason":`)
	writeString(&b, strconv.Quote(result.ReasonCode))
	writeString(&b, `,"signed":`)
	writeString(&b, strconv.FormatBool(signed))
	writeString(&b, `,"tampered_status":`)
	writeString(&b, strconv.Itoa(result.Tampered.Status))
	writeString(&b, `,"valid_status":`)
	writeString(&b, strconv.Itoa(result.Valid.Status))
	writeByte(&b, '}')

	return b.String()
}

func gradeOrFail(grade *string) string {
	if grade == nil || *grade == "" {
		return validatorcore.GradeFail
	}

	return *grade
}

func shouldPersistHTTPSig(result httpsigprobe.Result) bool {
	if result.ProbeURL == "" {
		return false
	}

	return shouldPersistHTTPSigLeg(result.Valid) || shouldPersistHTTPSigLeg(result.Tampered)
}

func shouldPersistHTTPSigLeg(leg httpsigprobe.Exchange) bool {
	if leg.SigRaw != "" || leg.Err != nil || leg.Status != 0 {
		return true
	}

	return len(leg.Body) > 0
}

func attemptRequestID(base string, attempt int) string {
	if attempt <= 1 {
		return base
	}

	return base + "-" + strconv.Itoa(attempt)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
