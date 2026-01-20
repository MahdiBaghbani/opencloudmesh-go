package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLegacyRateLimitCode enforces that the legacy server-level rate limiter
// (simpleRateLimiter) is deleted by the end of Phase 20.
//
// This test uses an allowlist that must shrink over time:
// - Remove the server middleware allowances in Phase 20 when the legacy limiter is deleted.
func TestNoLegacyRateLimitCode(t *testing.T) {
	// This allowlist exists to keep make test-go passing in every phase.
	// Remove the server middleware allowances in Phase 20 when the legacy limiter is deleted.
	allowedSubstrings := []string{
		"/guards/",
		"/server/middleware.go",          // allowed until Phase 20 completes (pre-move)
		"/platform/server/middleware.go", // allowed until Phase 20 completes (post-move)
	}

	root := filepath.Clean("../")
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		p := filepath.ToSlash(path)
		for _, allow := range allowedSubstrings {
			if strings.Contains(p, allow) {
				return nil
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "simpleRateLimiter") {
			violations = append(violations, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found legacy server rate limiter symbol simpleRateLimiter outside allowed files:\n%s",
			strings.Join(violations, "\n"))
	}
}
