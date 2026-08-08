// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

func (v *RFC9421Verifier) validateCreated(created int64) (string, error) {
	now := v.opts.Now().Unix()
	maxSkew := int64(v.opts.CreatedMaxSkew / time.Second)
	maxAge := int64(v.opts.CreatedMaxAge / time.Second)

	if created > now+maxSkew {
		return ReasonFutureCreated, errors.New("created timestamp is too far in the future")
	}

	if now-created > maxAge {
		return ReasonStaleCreated, errors.New("created timestamp is stale")
	}

	return "", nil
}

func validateRequiredComponents(actual, required []string) error {
	present := map[string]struct{}{}
	for _, c := range actual {
		present[strings.ToLower(c)] = struct{}{}
	}

	for _, reqComp := range required {
		if _, ok := present[strings.ToLower(reqComp)]; !ok {
			return fmt.Errorf("missing required signature component %q", reqComp)
		}
	}

	return nil
}

func verifyRequiredBodyHeaders(req *http.Request, body []byte, requiredComponents []string) error {
	required := map[string]struct{}{}
	for _, comp := range requiredComponents {
		required[strings.ToLower(comp)] = struct{}{}
	}

	if _, ok := required["content-digest"]; ok {
		if req.Header.Get("Content-Digest") == "" {
			return errors.New("missing Content-Digest header")
		}
	}

	if _, ok := required["content-length"]; ok {
		cl := req.Header.Get("Content-Length")
		if cl == "" {
			if len(body) > 0 {
				return errors.New("missing Content-Length header")
			}

			if req.ContentLength != 0 {
				return errors.New("content length mismatch")
			}

			return nil
		}

		n, err := strconv.Atoi(cl)
		if err != nil {
			return errors.New("invalid Content-Length header")
		}

		if n != len(body) {
			return errors.New("content length mismatch")
		}
	}

	return nil
}

// HasSignatureHeaders checks if the request has signature headers.
func (v *RFC9421Verifier) HasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature-Input") != "" || req.Header.Get("Signature") != ""
}

// HasOCMSignatureAttempt checks if the request has any OCM signature attempt
// by tag or label.
func (v *RFC9421Verifier) HasOCMSignatureAttempt(req *http.Request) bool {
	return sigparams.HasOCMSignatureAttempt(req.Header.Get("Signature-Input")) ||
		sigparams.HasOCMSignatureAttempt(req.Header.Get("Signature"))
}

func buildSignatureBase(req *http.Request, components []string) (string, error) {
	var lines []string

	for _, comp := range components {
		comp = strings.ToLower(comp)

		value, err := componentValue(req, comp, false)
		if err != nil {
			return "", err
		}

		if err := rejectCRLF(comp, value); err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("\"%s\": %s", comp, value))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// BuildSignatureBase builds RFC 9421 signature-base lines for components
// (without the trailing @signature-params line).
func BuildSignatureBase(req *http.Request, components []string) (string, error) {
	return buildSignatureBase(req, components)
}

func buildSignatureBaseFromRequest(req *http.Request, _ []byte, components []string) (string, error) {
	var lines []string

	for _, comp := range components {
		comp = strings.ToLower(comp)

		value, err := componentValue(req, comp, true)
		if err != nil {
			return "", err
		}

		if err := rejectCRLF(comp, value); err != nil {
			return "", err
		}

		lines = append(lines, fmt.Sprintf("\"%s\": %s", comp, value))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

func rejectCRLF(comp, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("component %q value contains CR/LF", comp)
	}

	return nil
}

func componentValue(req *http.Request, comp string, received bool) (string, error) {
	switch comp {
	case "@method":
		return req.Method, nil
	case "@target-uri":
		return CanonicalTargetURI(req), nil
	case "@authority":
		value := req.Host
		if value == "" {
			value = req.URL.Host
		}

		return value, nil
	case "@path":
		return req.URL.Path, nil
	case "@query":
		if req.URL.RawQuery == "" {
			return "?", nil
		}

		return "?" + req.URL.RawQuery, nil
	case "content-digest":
		return req.Header.Get("content-digest"), nil
	case "content-length":
		if v := req.Header.Get("content-length"); v != "" {
			return v, nil
		}

		return strconv.FormatInt(req.ContentLength, 10), nil
	case "date":
		return req.Header.Get("date"), nil
	default:
		value := req.Header.Get(comp)
		if value == "" && received {
			return "", fmt.Errorf("missing header %q", comp)
		}

		return value, nil
	}
}

// CanonicalTargetURI returns one scheme://host+RequestURI form for both
// signing and verification so proxy-reconstructed requests stay consistent.
func CanonicalTargetURI(req *http.Request) string {
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	return scheme + "://" + host + req.URL.RequestURI()
}

// VerifyContentDigest verifies the Content-Digest header matches the body.
// When the header is absent, verification is skipped so optional unsigned
// paths can accept requests without a digest. When the header is present,
// every listed digest algorithm must be recognized and match the body per
// the OCM verification requirements.
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L924-L926
func VerifyContentDigest(req *http.Request, body []byte) error {
	digestHeader := req.Header.Get("Content-Digest")
	if digestHeader == "" {
		return nil
	}

	entries, err := parseContentDigestHeader(digestHeader)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		hasher, ok := recognizedDigestHashers[entry.algorithm]
		if !ok {
			return fmt.Errorf("unsupported digest algorithm %q", entry.algorithm)
		}

		actual := hasher(body)
		if !bytes.Equal(entry.value, actual) {
			return fmt.Errorf("content digest mismatch for %s", entry.algorithm)
		}
	}

	return nil
}

type contentDigestEntry struct {
	algorithm string
	value     []byte
}

var recognizedDigestHashers = map[string]func([]byte) []byte{
	"sha-256": sigalg.SumSHA256,
	"sha-512": sigalg.SumSHA512,
}

func parseContentDigestHeader(header string) ([]contentDigestEntry, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, errors.New("empty Content-Digest header")
	}

	var entries []contentDigestEntry

	for memberStart := 0; memberStart < len(header); {
		memberStart = skipContentDigestSeparators(header, memberStart)
		if memberStart >= len(header) {
			break
		}

		memberEnd := scanContentDigestMemberEnd(header, memberStart)

		entry, err := parseContentDigestEntry(header[memberStart:memberEnd])
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry)

		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}

	if len(entries) == 0 {
		return nil, errors.New("malformed Content-Digest header")
	}

	return entries, nil
}

func skipContentDigestSeparators(header string, start int) int {
	for start < len(header) {
		ch := header[start]
		if ch == ' ' || ch == '\t' || ch == ',' {
			start++

			continue
		}

		break
	}

	return start
}

func parseContentDigestEntry(member string) (contentDigestEntry, error) {
	member = strings.TrimSpace(member)
	if member == "" {
		return contentDigestEntry{}, errors.New("malformed Content-Digest entry")
	}

	eq := strings.Index(member, "=")
	if eq <= 0 {
		return contentDigestEntry{}, fmt.Errorf("malformed Content-Digest entry %q", member)
	}

	algorithm := strings.TrimSpace(member[:eq])

	valuePart := strings.TrimSpace(member[eq+1:])
	if !strings.HasPrefix(valuePart, ":") || !strings.HasSuffix(valuePart, ":") {
		return contentDigestEntry{}, fmt.Errorf("malformed digest value for %s", algorithm)
	}

	raw, err := base64.StdEncoding.DecodeString(strings.Trim(valuePart, ":"))
	if err != nil {
		return contentDigestEntry{}, fmt.Errorf("invalid digest encoding for %s: %w", algorithm, err)
	}

	return contentDigestEntry{algorithm: algorithm, value: raw}, nil
}

func scanContentDigestMemberEnd(header string, start int) int {
	inByteSeq := false

	for i := start; i < len(header); i++ {
		ch := header[i]
		if inByteSeq {
			if ch == ':' {
				inByteSeq = false
			}

			continue
		}

		if ch == ':' {
			inByteSeq = true

			continue
		}

		if ch == ',' {
			return i
		}
	}

	return len(header)
}

// ReadAndRestoreBody reads the request body and restores it for re-reading.
func ReadAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("crypto: read request body: %w", err)
	}

	//nolint:errcheck // best-effort cleanup; error is not actionable
	_ = req.Body.Close()

	req.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}
