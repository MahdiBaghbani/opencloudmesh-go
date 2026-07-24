// Package crypto provides shared test helpers for platform crypto tests.
// Helpers consolidate duplicated setup used across jwks, sigalg, httpsig, and keys tests.
package crypto

// PadCoord zero-pads b on the left to size bytes when len(b) < size.
func PadCoord(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
