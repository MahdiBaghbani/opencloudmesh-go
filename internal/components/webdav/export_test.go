package webdav

import "net/http"

// ExtractWebDAVIDForTest exposes extractWebDAVID.
func ExtractWebDAVIDForTest(path string) string {
	return extractWebDAVID(path)
}

// IsValidWebDAVIDForTest exposes isValidWebDAVID.
func IsValidWebDAVIDForTest(id string) bool {
	return isValidWebDAVID(id)
}

// CredentialResult is the exported credentialResult for tests.
type CredentialResult = credentialResult

// ExtractCredentialForTest exposes extractCredential.
func ExtractCredentialForTest(r *http.Request) *CredentialResult {
	return extractCredential(r)
}
