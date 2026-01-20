package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoDirectForwardedHeaderParsing enforces that no code outside the realip
// library parses X-Forwarded-For or X-Real-IP headers directly.
//
// This test uses an allowlist that must shrink over time:
// - Remove trustedproxy allowances in Phase 12 (after the move to realip).
// - Remove ratelimit allowance in Phase 18 (when internal/ratelimit is deleted).
func TestNoDirectForwardedHeaderParsing(t *testing.T) {
	forbidden := []string{"X-Forwarded-For", "X-Real-IP"}

	// This allowlist exists to keep make test-go passing in every phase.
	// It must shrink over time:
	// - Remove trustedproxy allowances in Phase 12 (after the move to realip).
	// - Remove ratelimit allowance in Phase 18 (when internal/ratelimit is deleted).
	allowedSubstrings := []string{
		"/platform/http/realip/",
		"/guards/",
		"/server/trustedproxy",          // allowed until Phase 12 completes
		"/platform/server/trustedproxy", // allowed until Phase 12 completes
		"/ratelimit/",                   // allowed until Phase 18 deletes internal/ratelimit
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
		content := string(data)
		for _, token := range forbidden {
			if strings.Contains(content, token) {
				violations = append(violations, p)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found X-Forwarded-For/X-Real-IP references outside realip (see allowlist rules in this test):\n%s",
			strings.Join(violations, "\n"))
	}
}
