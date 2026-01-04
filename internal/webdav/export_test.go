package webdav

// Export internal functions for testing.

// ExtractWebDAVIDForTest exposes extractWebDAVID for testing.
func ExtractWebDAVIDForTest(path string) string {
	return extractWebDAVID(path)
}

// IsValidWebDAVIDForTest exposes isValidWebDAVID for testing.
func IsValidWebDAVIDForTest(id string) bool {
	return isValidWebDAVID(id)
}
