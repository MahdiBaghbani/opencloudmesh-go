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
			break
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
		eq := keyStart
		for eq < memberEnd && header[eq] != '=' {
			eq++
		}
		if eq < memberEnd {
			labels = append(labels, strings.TrimSpace(header[keyStart:eq]))
		}
		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}
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

// scanTagOCM scans s for a top-level tag parameter whose value is or starts
// with the OCM tag. It tolerates malformed or unclosed quoted values.
func scanTagOCM(s string) bool {
	if value, ok := parseTagParameter(s, 0); ok && isOCMTagValue(value) {
		return true
	}

	inQuote := false
	quoteChar := byte(0)
	parenDepth := 0
	inByteSeq := false
	i := 0
	for i < len(s) {
		ch := s[i]
		if inByteSeq {
			if ch == ':' {
				inByteSeq = false
			}
			i++
			continue
		}
		if inQuote {
			if ch == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			if ch == quoteChar {
				inQuote = false
			}
			i++
			continue
		}
		switch ch {
		case '"', '\'':
			inQuote = true
			quoteChar = ch
			i++
		case '(':
			parenDepth++
			i++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			i++
		case ':':
			if parenDepth == 0 {
				inByteSeq = true
			}
			i++
		case ';':
			if parenDepth == 0 {
				if value, ok := parseTagParameter(s, i+1); ok && isOCMTagValue(value) {
					return true
				}
			}
			i++
		default:
			i++
		}
	}
	return false
}

// parseTagParameter tries to parse a tag parameter starting at start in s.
// It returns the raw value and true if the parameter key is "tag".
func parseTagParameter(s string, start int) (string, bool) {
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	keyStart := start
	keyEnd := keyStart
	for keyEnd < len(s) && s[keyEnd] != '=' && s[keyEnd] != ';' && s[keyEnd] != ',' {
		keyEnd++
	}
	if strings.TrimSpace(s[keyStart:keyEnd]) != "tag" {
		return "", false
	}
	if keyEnd >= len(s) || s[keyEnd] != '=' {
		return "", false
	}
	valStart := keyEnd + 1
	for valStart < len(s) && (s[valStart] == ' ' || s[valStart] == '\t') {
		valStart++
	}
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
	return s[valStart:valEnd], true
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

// visitAllDictionaryMembers walks every top-level dictionary member in header
// and calls fn with the member label and raw entry value. fn returning false
// stops iteration.
func visitAllDictionaryMembers(header string, fn func(label, entry string) bool) {
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
		eq := keyStart
		for eq < memberEnd && header[eq] != '=' {
			eq++
		}
		if eq < memberEnd {
			label := strings.TrimSpace(header[keyStart:eq])
			entry := strings.TrimSpace(header[eq+1 : memberEnd])
			if !fn(label, entry) {
				return
			}
		}
		memberStart = memberEnd
		if memberStart < len(header) && header[memberStart] == ',' {
			memberStart++
		}
	}
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
