package sigalg

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64url value")
	}
	// RFC 7515 base64url without padding.
	padded := s
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}

	raw, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return nil, err
	}

	return raw, nil
}
