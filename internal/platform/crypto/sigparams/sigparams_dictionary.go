// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sigparams

import (
	"errors"
	"fmt"
	"strings"
)

func scanTagKey(s string, start int) (int, bool) {
	keyEnd := start
	for keyEnd < len(s) && s[keyEnd] != '=' && s[keyEnd] != ';' && s[keyEnd] != ',' {
		keyEnd++
	}

	if strings.TrimSpace(s[start:keyEnd]) != "tag" {
		return 0, false
	}

	if keyEnd >= len(s) || s[keyEnd] != '=' {
		return 0, false
	}

	return keyEnd, true
}

func scanTagValue(s string, valStart int) int {
	valEnd := valStart
	if valStart < len(s) && (s[valStart] == '"' || s[valStart] == '\'') {
		quote := s[valStart]

		valEnd = valStart + 1
		for valEnd < len(s) {
			if s[valEnd] == '\\' && valEnd+1 < len(s) {
				valEnd += 2
				continue
			}

			if s[valEnd] == quote {
				valEnd++ // include closing quote
				break
			}

			valEnd++
		}
	} else {
		for valEnd < len(s) && s[valEnd] != ';' && s[valEnd] != ',' {
			valEnd++
		}
	}

	return valEnd
}

// isOCMTagValue reports whether a raw tag value is or begins with the OCM
// tag value, allowing partial or malformed values.
func isOCMTagValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	if value == SignatureTagOCM {
		return true
	}

	if value[0] == '"' {
		return strings.HasPrefix(value, `"`+SignatureTagOCM)
	}

	if value[0] == '\'' {
		return strings.HasPrefix(value, `'`+SignatureTagOCM)
	}

	return strings.HasPrefix(value, SignatureTagOCM)
}

func skipMemberSeparators(s string, start int) int {
	for start < len(s) {
		ch := s[start]
		if ch == ' ' || ch == '\t' || ch == ',' {
			start++
			continue
		}

		break
	}

	return start
}

// visitDictionaryMembersRaw walks every top-level dictionary member in header
// and calls fn with [memberStart, memberEnd) offsets. fn returning false stops.
func visitDictionaryMembersRaw(header string, fn func(memberStart, memberEnd int) bool) {
	for memberStart := 0; memberStart < len(header); {
		memberStart = skipMemberSeparators(header, memberStart)
		if memberStart >= len(header) {
			return
		}

		memberEnd := scanTopLevelMemberEnd(header, memberStart)
		if !fn(memberStart, memberEnd) {
			return
		}

		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}
}

func parseDictionaryMember(header string, memberStart, memberEnd int, fn func(label, entry string) bool) bool {
	keyStart := skipSpacesTabs(header, memberStart)

	eq := keyStart
	for eq < memberEnd && header[eq] != '=' {
		eq++
	}

	if eq >= memberEnd {
		return true
	}

	label := strings.TrimSpace(header[keyStart:eq])
	entry := strings.TrimSpace(header[eq+1 : memberEnd])

	return fn(label, entry)
}

// visitAllDictionaryMembers walks every top-level dictionary member in header
// and calls fn with the member label and raw entry value. fn returning false
// stops iteration.
func visitAllDictionaryMembers(header string, fn func(label, entry string) bool) {
	visitDictionaryMembersRaw(header, func(memberStart, memberEnd int) bool {
		return parseDictionaryMember(header, memberStart, memberEnd, fn)
	})
}

// CountDictionaryMembers counts RFC 8941 dictionary members named label.
// Matches only at top-level member keys so values like keyid="x, ocm=spoof"
// do not count.
func CountDictionaryMembers(header, label string) int {
	count := 0

	visitDictionaryMembers(header, label, func(_, _ int) bool {
		count++
		return true
	})

	return count
}

// ExtractDictionaryMember returns the value of the first dictionary member
// named label, using the same boundary rules as CountDictionaryMembers.
func ExtractDictionaryMember(header, label string) (string, error) {
	return extractDictionaryEntry(header, label, "dictionary")
}

func extractDictionaryEntry(header, label, headerName string) (string, error) {
	var entry string

	found := false

	visitDictionaryMembers(header, label, func(start, end int) bool {
		entry = strings.TrimSpace(header[start:end])
		found = true

		return false
	})

	if !found {
		return "", fmt.Errorf("sigparams: label %q not found in %s header", label, headerName)
	}

	if entry == "" {
		return "", fmt.Errorf("sigparams: empty entry for label %q", label)
	}

	return entry, nil
}

// visitDictionaryMembers walks top-level dictionary members (commas outside
// quotes, inner lists, and byte sequences) and calls fn with [valueStart,
// valueEnd) for each member whose key equals label. fn returning false stops.
func visitDictionaryMembers(header, label string, fn func(start, end int) bool) {
	prefix := label + "="

	visitDictionaryMembersRaw(header, func(memberStart, memberEnd int) bool {
		keyStart := skipSpacesTabs(header, memberStart)

		if keyStart+len(prefix) <= memberEnd && header[keyStart:keyStart+len(prefix)] == prefix {
			if !fn(keyStart+len(prefix), memberEnd) {
				return false
			}
		}

		return true
	})
}

type topLevelScanState struct {
	inQuote    bool
	parenDepth int
	inByteSeq  bool
}

func (state *topLevelScanState) stepByteSeq(i *int, ch byte) bool {
	if !state.inByteSeq {
		return false
	}

	if ch == ':' {
		state.inByteSeq = false
	}

	*i++

	return true
}

func (state *topLevelScanState) stepQuote(header string, i *int, ch byte) bool {
	if !state.inQuote {
		return false
	}

	if ch == '\\' && *i+1 < len(header) {
		*i += 2
	} else {
		if ch == '"' {
			state.inQuote = false
		}

		*i++
	}

	return true
}

func (state *topLevelScanState) stepUnquoted(i *int, ch byte) bool {
	switch ch {
	case '"':
		state.inQuote = true
	case '(':
		state.parenDepth++
	case ')':
		if state.parenDepth > 0 {
			state.parenDepth--
		}
	case ':':
		if state.parenDepth == 0 {
			state.inByteSeq = true
		}
	case ',':
		if state.parenDepth == 0 {
			return true
		}
	}

	*i++

	return false
}

// scanTopLevelMemberEnd returns the index of the next top-level comma, or
// len(header). Quoted strings, parenthesized inner lists, and :byte-seq:
// values are skipped so commas inside them do not split members.
func scanTopLevelMemberEnd(header string, start int) int {
	state := topLevelScanState{}

	i := start
	for i < len(header) {
		ch := header[i]
		if state.stepByteSeq(&i, ch) {
			continue
		}

		if state.stepQuote(header, &i, ch) {
			continue
		}

		if state.stepUnquoted(&i, ch) {
			return i
		}
	}

	return len(header)
}

func parseInnerList(entry string) ([]string, string, error) {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "(") {
		return nil, "", errors.New("expected inner list starting with (")
	}

	depth := 0
	closeIdx := -1

	for i, ch := range entry {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				closeIdx = i
			}
		}

		if closeIdx >= 0 {
			break
		}
	}

	if closeIdx < 0 {
		return nil, "", errors.New("malformed inner list")
	}

	inner := strings.TrimSpace(entry[1:closeIdx])

	rest := strings.TrimSpace(entry[closeIdx+1:])
	if rest != "" && !strings.HasPrefix(rest, ";") {
		return nil, "", errors.New("parameters must follow inner list")
	}

	var components []string

	seen := make(map[string]struct{})

	if inner != "" {
		for _, part := range strings.Fields(inner) {
			part = strings.Trim(part, `"`)
			if part == "" {
				continue
			}

			c := strings.ToLower(part)
			if _, dup := seen[c]; dup {
				// RFC 9421 section 2.3: covered components are ordered-but-distinct;
				// duplicate identifiers are not meaningful.
				return nil, "", errors.New("duplicate covered component")
			}

			seen[c] = struct{}{}
			components = append(components, c)
		}
	}

	return components, rest, nil
}

func splitParameters(rest string) []string {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nil
	}

	rest = strings.TrimPrefix(rest, ";")

	return strings.Split(rest, ";")
}

func parseStringParam(value string) (string, error) {
	if len(value) < 2 || !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
		return "", fmt.Errorf("expected quoted string, got %q", value)
	}

	inner := value[1 : len(value)-1]
	if inner == "" {
		return "", errors.New("empty string parameter")
	}

	return inner, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty base64 value")
	}
	// RFC 9421 uses standard base64 for signatures.
	raw, err := decodeStdBase64(s)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func encodeBase64(raw []byte) string {
	return encodeStdBase64(raw)
}
