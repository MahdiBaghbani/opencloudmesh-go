package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestWireDTOsOnlyInSpec enforces that OCM wire-format DTO struct definitions
// only exist in the spec package. Prevents DTOs from drifting back into
// handler or model packages.
//
// Checks for known wire DTO type declarations (from OCM-API spec). Domain
// models like IncomingShare or OutgoingShare that reuse field names are not
// wire DTOs and are allowed outside spec/.
func TestWireDTOsOnlyInSpec(t *testing.T) {
	// Wire DTO type names that must only be defined in spec/
	wireDTOTypes := []string{
		"NewShareRequest",
		"CreateShareResponse",
		"InviteAcceptedRequest",
		"InviteAcceptedResponse",
		"WebDAVProtocol",
		"WebAppProtocol",
		"OCMErrorResponse",
	}

	// Build a pattern matching any of these as a Go type declaration
	var patterns []*regexp.Regexp
	for _, name := range wireDTOTypes {
		patterns = append(patterns, regexp.MustCompile(`type\s+`+name+`\s+struct\b`))
	}

	repoRoot := findRepoRoot(t)
	ocmDir := filepath.Join(repoRoot, "internal", "components", "ocm")

	if _, err := os.Stat(ocmDir); os.IsNotExist(err) {
		t.Skip("ocm package not found")
	}

	var violations []string

	err := filepath.WalkDir(ocmDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Skip the spec package itself (that is where DTOs belong)
		relPath, _ := filepath.Rel(ocmDir, path)
		if strings.HasPrefix(filepath.ToSlash(relPath), "spec/") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		fileRel, _ := filepath.Rel(repoRoot, path)

		for i, pat := range patterns {
			if locs := pat.FindAllStringIndex(content, -1); len(locs) > 0 {
				for _, loc := range locs {
					line := 1 + strings.Count(content[:loc[0]], "\n")
					violations = append(violations,
						fileRel+":"+itoa(line)+": wire DTO type "+wireDTOTypes[i]+" defined outside spec/")
				}
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Wire DTO struct definitions found outside internal/components/ocm/spec/ "+
			"(move them to the spec package):\n%s",
			strings.Join(violations, "\n"))
	}
}
