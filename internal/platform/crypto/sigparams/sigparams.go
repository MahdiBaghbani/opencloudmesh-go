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

	entry, err := extractDictionaryEntry(header, label)
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

	entry, err := extractDictionaryEntry(header, label)
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
func FormatSignatureInput(label string, components []string, created int64, keyID, algorithm string) string {
	quoted := make([]string, len(components))
	for i, c := range components {
		quoted[i] = fmt.Sprintf("%q", strings.ToLower(c))
	}
	return fmt.Sprintf(
		`%s=(%s);created=%d;keyid=%q;alg=%q`,
		label,
		strings.Join(quoted, " "),
		created,
		keyID,
		algorithm,
	)
}

// FormatSignature builds a Signature dictionary member value.
func FormatSignature(label string, signature []byte) string {
	return fmt.Sprintf("%s=:%s:", label, encodeBase64(signature))
}

func extractDictionaryEntry(header, label string) (string, error) {
	prefix := label + "="
	idx := strings.Index(header, prefix)
	if idx < 0 {
		return "", fmt.Errorf("sigparams: label %q not found in Signature header", label)
	}

	start := idx + len(prefix)
	end := len(header)
	if comma := strings.Index(header[start:], ","); comma >= 0 {
		end = start + comma
	}

	entry := strings.TrimSpace(header[start:end])
	if entry == "" {
		return "", fmt.Errorf("sigparams: empty entry for label %q", label)
	}
	return entry, nil
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
