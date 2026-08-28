// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	exchangeDirectionOut   = "out"
	exchangeActorValidator = "validator"
)

func (p *ProbeRunner) insertExchange(ctx context.Context, row *validatorcore.ReportExchange) (uint, error) {
	if err := p.store.InsertReportExchange(ctx, row); err != nil {
		if validatorcore.IsDuplicateReportExchange(err) {
			return p.recoverExchangeID(ctx, row)
		}

		return 0, fmt.Errorf("passive probe persist %s exchange: %w", row.EndpointID, err)
	}

	return row.ExchangeID, nil
}

func (p *ProbeRunner) recoverExchangeID(ctx context.Context, row *validatorcore.ReportExchange) (uint, error) {
	id, err := p.store.LookupReportExchangeID(
		ctx,
		row.TestRunID,
		row.Direction,
		requestIDOf(row),
	)
	if err != nil {
		return 0, fmt.Errorf("passive probe recover %s exchange: %w", row.EndpointID, err)
	}

	return id, nil
}

func requestIDOf(row *validatorcore.ReportExchange) string {
	if row == nil || row.RequestID == nil {
		return ""
	}

	return *row.RequestID
}

func optionalExchangeID(id uint) *uint {
	if id == 0 {
		return nil
	}

	return &id
}

func baseExchange(testRunID, endpointID, requestID string) *validatorcore.ReportExchange {
	now := time.Now().Unix()
	actor := exchangeActorValidator
	leg := validatorcore.EvidenceLegPassive
	reqID := requestID

	return &validatorcore.ReportExchange{
		TestRunID:  testRunID,
		CapturedAt: now,
		Direction:  exchangeDirectionOut,
		Actor:      &actor,
		Leg:        &leg,
		EndpointID: endpointID,
		Method:     http.MethodGet,
		URL:        "",
		RequestID:  &reqID,
		CreatedAt:  now,
	}
}

func applyFetchTranscript(row *validatorcore.ReportExchange, bundle probeBundle) {
	var respHeaders http.Header

	var body []byte

	if bundle.fetch != nil {
		respHeaders = bundle.fetch.Headers
		body = bundle.fetch.Raw
	}

	if bundle.fetch != nil && bundle.fetch.Discovery != nil {
		status := http.StatusOK
		row.StatusCode = &status
	}

	applyBodyAndHeaders(row, nil, respHeaders, nil, body, bundle.fetchErr)
}

func applyBodyAndHeaders(
	row *validatorcore.ReportExchange,
	reqHeaders, respHeaders http.Header,
	reqBody, respBody []byte,
	fetchErr error,
) {
	if reqJSON := headersJSON(reqHeaders); reqJSON != "" {
		row.ReqHeadersJSON = &reqJSON
	}

	if respJSON := headersJSON(respHeaders); respJSON != "" {
		row.RespHeadersJSON = &respJSON
	}

	if redacted := redactBody(reqBody); redacted != "" {
		row.ReqBodyRedacted = &redacted
	}

	if redacted := redactBody(respBody); redacted != "" {
		row.RespBodyRedacted = &redacted
	}

	if hash := bodyHash(reqBody); hash != "" {
		row.ReqBodySHA256 = &hash
		n := int64(len(reqBody))
		row.ReqBodyBytes = &n
	}

	if hash := bodyHash(respBody); hash != "" {
		row.RespBodySHA256 = &hash
		n := int64(len(respBody))
		row.RespBodyBytes = &n
	}

	if fetchErr != nil {
		text := fetchErr.Error()
		row.ErrorText = &text
	}
}

func applyStatus(row *validatorcore.ReportExchange, status int) {
	if status == 0 {
		return
	}

	row.StatusCode = &status
}

func applySignature(row *validatorcore.ReportExchange, sigRaw string) {
	if sigRaw == "" {
		return
	}

	row.SigRaw = &sigRaw
	scheme := "httpsig"
	row.SigScheme = &scheme
}
