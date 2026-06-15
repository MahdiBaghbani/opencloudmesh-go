package jwks

import "encoding/base64"

func encodeBase64URLStd(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
