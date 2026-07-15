// Package sigparams parses RFC 9421 Signature and Signature-Input headers using
// Structured Field Values (RFC 8941) for the subset required by OCM.
package sigparams

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

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
	return out
}

// FormatSignature builds a Signature dictionary member value.
func FormatSignature(label string, signature []byte) string {
	return fmt.Sprintf("%s=:%s:", label, encodeBase64(signature))
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
	for memberStart := 0; memberStart < len(header); {
		for memberStart < len(header) {
			ch := header[memberStart]
			if ch == ' ' || ch == '\t' || ch == ',' {
				memberStart++
				continue
			}
			break
		}
		if memberStart >= len(header) {
			return
		}
		memberEnd := scanTopLevelMemberEnd(header, memberStart)
		keyStart := memberStart
		for keyStart < memberEnd {
			ch := header[keyStart]
			if ch == ' ' || ch == '\t' {
				keyStart++
				continue
			}
			break
		}
		if keyStart+len(prefix) <= memberEnd && header[keyStart:keyStart+len(prefix)] == prefix {
			if !fn(keyStart+len(prefix), memberEnd) {
				return
			}
		}
		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}
}

// scanTopLevelMemberEnd returns the index of the next top-level comma, or
// len(header). Quoted strings, parenthesized inner lists, and :byte-seq:
// values are skipped so commas inside them do not split members.
func scanTopLevelMemberEnd(header string, start int) int {
	inQuote := false
	parenDepth := 0
	inByteSeq := false
	for i := start; i < len(header); i++ {
		ch := header[i]
		if inByteSeq {
			if ch == ':' {
				inByteSeq = false
			}
			continue
		}
		if inQuote {
			if ch == '\\' && i+1 < len(header) {
				i++
				continue
			}
			if ch == '"' {
				inQuote = false
			}
			continue
		}
		switch ch {
		case '"':
			inQuote = true
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case ':':
			if parenDepth == 0 {
				inByteSeq = true
			}
		case ',':
			if parenDepth == 0 {
				return i
			}
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
				break
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
	if inner != "" {
		for _, part := range strings.Fields(inner) {
			part = strings.Trim(part, `"`)
			if part == "" {
				continue
			}
			components = append(components, strings.ToLower(part))
		}
	}

	return components, rest, nil
}

func splitParameters(rest string) []string {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nil
	}
	if strings.HasPrefix(rest, ";") {
		rest = strings.TrimPrefix(rest, ";")
	}
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
