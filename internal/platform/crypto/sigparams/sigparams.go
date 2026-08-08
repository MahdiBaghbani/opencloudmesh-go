// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package sigparams parses RFC 9421 Signature and Signature-Input headers using
// Structured Field Values (RFC 8941) for the subset required by OCM.
package sigparams

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SignatureTagOCM is the RFC 9421 tag parameter value for OCM signatures.
const SignatureTagOCM = SignatureLabelOCM

// Params holds parsed @signature-params for one label.
type Params struct {
	Label      string
	Components []string
	Created    int64
	KeyID      string
	Algorithm  string
	Raw        string
}

// ParseSignatureInput parses a Signature-Input header dictionary and returns
// params for the requested label.
func ParseSignatureInput(header, label string) (Params, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return Params{}, errors.New("sigparams: label is required")
	}

	if strings.TrimSpace(header) == "" {
		return Params{}, errors.New("sigparams: missing Signature-Input header")
	}

	entry, err := extractDictionaryEntry(header, label, "Signature-Input")
	if err != nil {
		return Params{}, err
	}

	components, rest, err := parseInnerList(entry)
	if err != nil {
		return Params{}, fmt.Errorf("sigparams: parse inner list: %w", err)
	}

	params := Params{
		Label:      label,
		Components: components,
		Raw:        entry,
	}

	for _, item := range splitParameters(rest) {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "created":
			created, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil {
				return Params{}, fmt.Errorf("sigparams: invalid created: %w", parseErr)
			}

			params.Created = created
		case "keyid":
			params.KeyID, err = parseStringParam(value)
			if err != nil {
				return Params{}, fmt.Errorf("sigparams: invalid keyid: %w", err)
			}
		case "alg":
			params.Algorithm, err = parseStringParam(value)
			if err != nil {
				return Params{}, fmt.Errorf("sigparams: invalid alg: %w", err)
			}
		}
	}

	return params, nil
}

// ParseSignature extracts the byte signature for label from a Signature header.
func ParseSignature(header, label string) ([]byte, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil, errors.New("sigparams: label is required")
	}

	if strings.TrimSpace(header) == "" {
		return nil, errors.New("sigparams: missing Signature header")
	}

	entry, err := extractDictionaryEntry(header, label, "Signature")
	if err != nil {
		return nil, err
	}

	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, ":") || !strings.HasSuffix(entry, ":") {
		return nil, fmt.Errorf("sigparams: signature for label %q is not a byte sequence", label)
	}

	raw, err := decodeBase64(strings.Trim(entry, ":"))
	if err != nil {
		return nil, fmt.Errorf("sigparams: invalid signature encoding: %w", err)
	}

	return raw, nil
}

// FormatSignatureInput builds a Signature-Input dictionary member value.
// When algorithm is empty, the alg parameter is omitted.
// The formatter always appends the OCM tag parameter.
func FormatSignatureInput(label string, components []string, created int64, keyID, algorithm string) string {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = fmt.Sprintf("%q", strings.ToLower(c))
	}

	out := fmt.Sprintf(
		`%s=(%s);created=%d;keyid=%q`,
		label,
		strings.Join(quoted, " "),
		created,
		keyID,
	)
	if algorithm != "" {
		out += fmt.Sprintf(`;alg=%q`, algorithm)
	}

	out += fmt.Sprintf(`;tag=%q`, SignatureTagOCM)

	return out
}

// FormatSignature builds a Signature dictionary member value.
func FormatSignature(label string, signature []byte) string {
	return fmt.Sprintf("%s=:%s:", label, encodeBase64(signature))
}

// ListDictionaryMemberLabels returns top-level dictionary member keys in order.
func ListDictionaryMemberLabels(header string) []string {
	var labels []string

	visitDictionaryMembersRaw(header, func(memberStart, memberEnd int) bool {
		keyStart := skipSpacesTabs(header, memberStart)

		eq := keyStart
		for eq < memberEnd && header[eq] != '=' {
			eq++
		}

		if eq < memberEnd {
			labels = append(labels, strings.TrimSpace(header[keyStart:eq]))
		}

		return true
	})

	return labels
}

// ValidateExactlyOneLabel requires exactly one dictionary member named
// allowedLabel. Foreign labels are ignored.
func ValidateExactlyOneLabel(header, allowedLabel string) error {
	allowedCount := 0

	for _, label := range ListDictionaryMemberLabels(header) {
		if label == allowedLabel {
			allowedCount++
		}
	}

	if allowedCount == 0 {
		return fmt.Errorf("sigparams: missing %q dictionary member", allowedLabel)
	}

	if allowedCount > 1 {
		return fmt.Errorf("sigparams: multiple %q signatures", allowedLabel)
	}

	return nil
}

// CountTags returns the number of top-level dictionary members whose tag
// parameter equals tagValue.
func CountTags(header, tagValue string) int {
	count := 0

	visitAllDictionaryMembers(header, func(_ string, entry string) bool {
		if entryHasTag(entry, tagValue) {
			count++
		}

		return true
	})

	return count
}

// FindTaggedLabel returns the label of the first dictionary member whose tag
// parameter equals tagValue.
func FindTaggedLabel(header, tagValue string) (string, error) {
	var label string

	found := false

	visitAllDictionaryMembers(header, func(l string, entry string) bool {
		if entryHasTag(entry, tagValue) {
			label = l
			found = true

			return false
		}

		return true
	})

	if !found {
		return "", fmt.Errorf("sigparams: no member with tag %q", tagValue)
	}

	return label, nil
}

func entryHasTag(entry, tagValue string) bool {
	_, rest, err := parseInnerList(entry)
	if err != nil {
		return false
	}

	for _, item := range splitParameters(rest) {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if key != "tag" {
			continue
		}

		val, err := parseStringParam(value)
		if err != nil {
			continue
		}

		if val == tagValue {
			return true
		}
	}

	return false
}

// HasOCMTagAttempt reports whether the header contains a dictionary member
// whose tag parameter is or starts with the OCM tag value, including partial
// or malformed tag parameters. It is used to distinguish a genuine unsigned
// request from a request that attempted an OCM signature but broke.
func HasOCMTagAttempt(header string) bool {
	found := false

	visitAllDictionaryMembers(header, func(_ string, entry string) bool {
		if entryHasOCMTagAttempt(entry) {
			found = true

			return false
		}

		return true
	})

	return found
}

// HasOCMLabel reports whether the header contains a dictionary member whose
// label is the OCM label.
func HasOCMLabel(header string) bool {
	found := false

	visitAllDictionaryMembers(header, func(label, _ string) bool {
		if label == SignatureLabelOCM {
			found = true

			return false
		}

		return true
	})

	return found
}

// HasOCMSignatureAttempt reports whether the header contains any OCM
// signature attempt, by tag or by label.
func HasOCMSignatureAttempt(header string) bool {
	return HasOCMTagAttempt(header) || HasOCMLabel(header)
}

// entryHasOCMTagAttempt reports whether the raw entry contains a tag
// parameter that is or starts with the OCM tag value.
func entryHasOCMTagAttempt(entry string) bool {
	var rest string
	if _, r, err := parseInnerList(entry); err == nil {
		rest = r
	} else {
		rest = entry
	}

	return scanTagOCM(rest)
}

type tagScanState struct {
	inQuote    bool
	quoteChar  byte
	parenDepth int
	inByteSeq  bool
}

func (state *tagScanState) stepByteSeq(i *int, ch byte) bool {
	if !state.inByteSeq {
		return false
	}

	if ch == ':' {
		state.inByteSeq = false
	}

	*i++

	return true
}

func (state *tagScanState) stepQuote(s string, i *int, ch byte) bool {
	if !state.inQuote {
		return false
	}

	if ch == '\\' && *i+1 < len(s) {
		*i += 2

		return true
	}

	if ch == state.quoteChar {
		state.inQuote = false
	}

	*i++

	return true
}

func (state *tagScanState) stepUnquoted(s string, i *int, ch byte) bool {
	switch ch {
	case '"', '\'':
		state.inQuote = true
		state.quoteChar = ch
		*i++
	case '(':
		state.parenDepth++
		*i++
	case ')':
		if state.parenDepth > 0 {
			state.parenDepth--
		}

		*i++
	case ':':
		if state.parenDepth == 0 {
			state.inByteSeq = true
		}

		*i++
	case ';':
		if state.parenDepth == 0 {
			if value, ok := parseTagParameter(s, *i+1); ok && isOCMTagValue(value) {
				return true
			}
		}

		*i++
	default:
		*i++
	}

	return false
}

// scanTagOCM scans s for a top-level tag parameter whose value is or starts
// with the OCM tag. It tolerates malformed or unclosed quoted values.
func scanTagOCM(s string) bool {
	if value, ok := parseTagParameter(s, 0); ok && isOCMTagValue(value) {
		return true
	}

	state := tagScanState{}

	i := 0
	for i < len(s) {
		ch := s[i]
		if state.stepByteSeq(&i, ch) {
			continue
		}

		if state.stepQuote(s, &i, ch) {
			continue
		}

		if state.stepUnquoted(s, &i, ch) {
			return true
		}
	}

	return false
}

// parseTagParameter tries to parse a tag parameter starting at start in s.
// It returns the raw value and true if the parameter key is "tag".
func parseTagParameter(s string, start int) (string, bool) {
	start = skipSpacesTabs(s, start)

	keyEnd, ok := scanTagKey(s, start)
	if !ok {
		return "", false
	}

	valStart := skipSpacesTabs(s, keyEnd+1)
	valEnd := scanTagValue(s, valStart)

	return s[valStart:valEnd], true
}

func skipSpacesTabs(s string, start int) int {
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}

	return start
}
