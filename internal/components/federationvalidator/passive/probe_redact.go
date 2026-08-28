// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	redactedBodyMarker  = "[redacted]"
	headerAuthorization = "Authorization"
	headerCookie        = "Cookie"
	headerSetCookie     = "Set-Cookie"
)

func headersJSON(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}

	safe := http.Header{}

	for key, values := range headers {
		if isSecretHeader(key) {
			continue
		}

		safe[key] = append([]string{}, values...)
	}

	if len(safe) == 0 {
		return ""
	}

	return encodeHeaderJSON(safe)
}

func isSecretHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case headerAuthorization, headerCookie, headerSetCookie:
		return true
	default:
		return false
	}
}

func redactBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	return redactedBodyMarker
}

func bodyHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}

func encodeHeaderJSON(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	var b strings.Builder

	writeByte(&b, '{')

	for i, key := range keys {
		if i > 0 {
			writeByte(&b, ',')
		}

		writeString(&b, strconv.Quote(key))
		writeByte(&b, ':')
		writeString(&b, encodeStringSliceJSON(headers[key]))
	}

	writeByte(&b, '}')

	return b.String()
}

func encodeStringSliceJSON(values []string) string {
	var b strings.Builder

	writeByte(&b, '[')

	for i, value := range values {
		if i > 0 {
			writeByte(&b, ',')
		}

		writeString(&b, strconv.Quote(value))
	}

	writeByte(&b, ']')

	return b.String()
}

func writeString(b *strings.Builder, s string) {
	if _, err := b.WriteString(s); err != nil {
		return
	}
}

func writeByte(b *strings.Builder, c byte) {
	if err := b.WriteByte(c); err != nil {
		return
	}
}
