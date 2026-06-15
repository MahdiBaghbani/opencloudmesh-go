package sigparams

import "encoding/base64"

func decodeStdBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func encodeStdBase64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}
