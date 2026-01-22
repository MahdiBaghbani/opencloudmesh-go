package webdav

import "net/http"

// Export internal functions for testing.

// ExtractWebDAVIDForTest exposes extractWebDAVID for testing.
func ExtractWebDAVIDForTest(path string) string {
	return extractWebDAVID(path)
}

// IsValidWebDAVIDForTest exposes isValidWebDAVID for testing.
func IsValidWebDAVIDForTest(id string) bool {
	return isValidWebDAVID(id)
}

// CredentialResult is exported for testing.
type CredentialResult = credentialResult

// ExtractCredentialForTest exposes extractCredential for testing.
func ExtractCredentialForTest(r *http.Request) *CredentialResult {
	return extractCredential(r)
}
