// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package jwksprobe fetches and grades a peer JWKS document without store I/O.
package jwksprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

const (
	// GradePass is a successful JWKS fetch and decode.
	GradePass = "pass"
	// GradeWarn is a JWKS caveat that does not fail the document.
	GradeWarn = "warn"
	// GradeFail is a failed JWKS fetch or decode.
	GradeFail = "fail"

	// ReasonEmptyURI is returned when the advertised JWKS URI is empty.
	ReasonEmptyURI = "jwks_uri_empty"
	// ReasonUnreachable is returned when the JWKS document cannot be fetched.
	ReasonUnreachable = "jwks_unreachable"
	// ReasonInvalid is returned when the document is not a usable key set.
	ReasonInvalid = "jwks_invalid"
	// ReasonOK is returned when the document contains at least one key.
	ReasonOK = "jwks_ok"
)

// Doer performs one outbound HTTP request.
type Doer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Result is a store-free JWKS grade plus the captured fetch transcript.
type Result struct {
	Grade      string
	ReasonCode string
	URI        string
	Method     string
	Status     int
	Headers    http.Header
	Body       []byte
	Err        error
}

// Grade fetches jwksURI and grades the document. An empty or whitespace-only
// URI is fail. An unreachable or empty key set is fail.
func Grade(ctx context.Context, client Doer, jwksURI string) Result {
	result := Result{
		URI:        strings.TrimSpace(jwksURI),
		Method:     http.MethodGet,
		Headers:    http.Header{},
		Body:       []byte{},
		Grade:      GradeFail,
		ReasonCode: ReasonEmptyURI,
	}

	if result.URI == "" {
		result.Err = errEmptyURI

		return result
	}

	if client == nil {
		result.ReasonCode = ReasonUnreachable
		result.Err = errNilClient

		return result
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, result.URI, http.NoBody)
	if err != nil {
		result.ReasonCode = ReasonUnreachable
		result.Err = fmt.Errorf("jwksprobe: build request: %w", err)

		return result
	}

	req.Header.Set("Accept", "application/json")

	resp, doErr := client.Do(ctx, req)
	if doErr != nil {
		result.ReasonCode = ReasonUnreachable
		result.Err = fmt.Errorf("jwksprobe: fetch: %w", doErr)

		return result
	}

	defer closeResponseBody(resp)

	result.Status = resp.StatusCode
	result.Headers = cloneHeaders(resp.Header)

	body, readErr := readLimitedBody(resp.Body, maxResponseBytes(client))
	if readErr != nil {
		result.ReasonCode = ReasonUnreachable
		result.Err = fmt.Errorf("jwksprobe: read body: %w", readErr)

		return result
	}

	result.Body = body

	if resp.StatusCode != http.StatusOK {
		result.ReasonCode = ReasonUnreachable
		result.Err = fmt.Errorf("jwksprobe: status %d", resp.StatusCode)

		return result
	}

	var set jwks.Set
	if err := json.Unmarshal(body, &set); err != nil {
		result.ReasonCode = ReasonInvalid
		result.Err = fmt.Errorf("jwksprobe: decode: %w", err)

		return result
	}

	if len(set.Keys) == 0 {
		result.ReasonCode = ReasonInvalid
		result.Err = errEmptySet

		return result
	}

	result.Grade = GradePass
	result.ReasonCode = ReasonOK
	result.Err = nil

	return result
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
