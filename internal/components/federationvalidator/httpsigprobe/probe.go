// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package httpsigprobe runs a signed two-request differential against a
// probe-only dummy URL. It never targets a product inbox.
package httpsigprobe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

const (
	// EndpointID is the persisted report-exchange endpoint id for this probe.
	EndpointID = "httpsig-probe"

	// GradePass is a successful HTTPSig differential.
	GradePass = "pass"
	// GradeWarn is reserved for a non-failing HTTPSig caveat.
	GradeWarn = "warn"
	// GradeFail is a failed HTTPSig probe.
	GradeFail = "fail"

	// ReasonSignerMissing is returned when no signer is wired.
	ReasonSignerMissing = "httpsig_signer_missing"
	// ReasonClientMissing is returned when no HTTP client is wired.
	ReasonClientMissing = "httpsig_client_missing"
	// ReasonSendFailed is returned when a probe request cannot be sent.
	ReasonSendFailed = "httpsig_send_failed"
	// ReasonNoDifferential is returned when both signed legs share a status.
	ReasonNoDifferential = "httpsig_no_differential"
	// ReasonOK is returned when the valid and tampered legs differ.
	ReasonOK = "httpsig_ok"

	probePath = "/.well-known/ocm-httpsig-probe"
)

// RequestSigner signs an HTTP request. Implementations must always sign.
type RequestSigner interface {
	SignRequest(req *http.Request, body []byte) error
}

// SignedDoer sends a signed request and must not follow redirects.
type SignedDoer interface {
	DoSigned(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Input is one HTTPSig probe attempt.
type Input struct {
	HTTP   SignedDoer
	Signer RequestSigner
	Origin string
}

// Exchange is one captured signed request and its response.
type Exchange struct {
	Method     string
	URL        string
	Status     int
	ReqHeaders http.Header
	Headers    http.Header
	Body       []byte
	SigRaw     string
	Err        error
}

// Result is a store-free HTTPSig grade plus both request transcripts.
type Result struct {
	Grade      string
	ReasonCode string
	ProbeURL   string
	Valid      Exchange
	Tampered   Exchange
}

// ProbeURL returns the probe-only dummy URL for origin. It never joins a
// product endpoint path.
func ProbeURL(origin string) string {
	return strings.TrimRight(strings.TrimSpace(origin), "/") + probePath
}

// Probe signs and sends a valid request and a tampered request to the dummy
// URL, then grades the status differential.
func Probe(ctx context.Context, in Input) Result {
	result := Result{
		ProbeURL:   ProbeURL(in.Origin),
		Grade:      GradeFail,
		ReasonCode: ReasonSendFailed,
		Valid:      emptyExchange(ProbeURL(in.Origin)),
		Tampered:   emptyExchange(ProbeURL(in.Origin)),
	}

	if in.Signer == nil {
		result.ReasonCode = ReasonSignerMissing

		return result
	}

	if in.HTTP == nil {
		result.ReasonCode = ReasonClientMissing

		return result
	}

	valid, err := sendSigned(ctx, in, result.ProbeURL, false)
	result.Valid = valid

	if err != nil {
		result.ReasonCode = ReasonSendFailed

		return result
	}

	tampered, tamperErr := sendSigned(ctx, in, result.ProbeURL, true)
	result.Tampered = tampered

	if tamperErr != nil {
		result.ReasonCode = ReasonSendFailed

		return result
	}

	if valid.Status == tampered.Status {
		result.ReasonCode = ReasonNoDifferential

		return result
	}

	result.Grade = GradePass
	result.ReasonCode = ReasonOK

	return result
}

func emptyExchange(url string) Exchange {
	return Exchange{
		Method:     http.MethodGet,
		URL:        url,
		ReqHeaders: http.Header{},
		Headers:    http.Header{},
		Body:       []byte{},
	}
}

func sendSigned(ctx context.Context, in Input, probeURL string, tamper bool) (Exchange, error) {
	out := emptyExchange(probeURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, http.NoBody)
	if err != nil {
		out.Err = fmt.Errorf("httpsigprobe: build request: %w", err)

		return out, out.Err
	}

	if signErr := in.Signer.SignRequest(req, []byte{}); signErr != nil {
		out.Err = fmt.Errorf("httpsigprobe: sign request: %w", signErr)

		return out, out.Err
	}

	if tamper {
		tamperSignature(req)
	}

	out.ReqHeaders = cloneHeaders(req.Header)
	out.SigRaw = req.Header.Get("Signature")

	resp, doErr := in.HTTP.DoSigned(ctx, req)
	if doErr != nil {
		out.Err = fmt.Errorf("httpsigprobe: send: %w", doErr)

		return out, out.Err
	}

	defer closeResponseBody(resp)

	out.Status = resp.StatusCode
	out.Headers = cloneHeaders(resp.Header)

	body, readErr := readLimitedBody(resp.Body, maxResponseBytes(in.HTTP))
	if readErr != nil {
		out.Err = fmt.Errorf("httpsigprobe: read body: %w", readErr)

		return out, out.Err
	}

	out.Body = body

	return out, nil
}

func tamperSignature(req *http.Request) {
	sig := req.Header.Get("Signature")
	if sig == "" {
		return
	}

	req.Header.Set("Signature", sig+"x")
}

func cloneHeaders(headers http.Header) http.Header {
	if headers == nil {
		return http.Header{}
	}

	return headers.Clone()
}

type responseByteLimiter interface {
	MaxResponseBytes() int64
}

func maxResponseBytes(v any) int64 {
	if limiter, ok := v.(responseByteLimiter); ok {
		if n := limiter.MaxResponseBytes(); n > 0 {
			return n
		}
	}

	// Configured outbound limit is unavailable; use the default.
	return int64(config.DefaultMaxResponseBytes)
}

func readLimitedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = int64(config.DefaultMaxResponseBytes)
	}

	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if int64(len(body)) > maxBytes {
		return nil, errTooLarge
	}

	return body, nil
}

func closeResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	//nolint:errcheck // best-effort cleanup; error is not actionable
	resp.Body.Close()
}
