package guards

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoBannedDSAbbreviations enforces that the abbreviation "DS" for
// Directory Service does not appear in any Go file. Use the full term
// "directory service" or the package name "directoryservice" instead.
func TestNoBannedDSAbbreviations(t *testing.T) {
	standaloneDS := regexp.MustCompile(`\bDS\b`)
	bannedTerms := []string{
		"dsClient", "dsURL", "ds_url",
		"DSMember", "refreshTimeoutPerDS", "dsCount",
	}

	// Skip self-references in this test file.
	allowedSubstrings := []string{"/guards/"}

	repoRoot := findRepoRoot(t)
	var violations []string

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
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
		relPath, _ := filepath.Rel(repoRoot, path)

		if locs := standaloneDS.FindAllStringIndex(content, -1); len(locs) > 0 {
			for _, loc := range locs {
				line := 1 + strings.Count(content[:loc[0]], "\n")
				violations = append(violations,
					relPath+":"+itoa(line)+": standalone \"DS\" abbreviation")
			}
		}

		for _, term := range bannedTerms {
			if strings.Contains(content, term) {
				violations = append(violations,
					relPath+": banned abbreviation \""+term+"\"")
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found banned DS abbreviations (use \"directory service\" or \"directoryservice\"):\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestNoFederationPackageImports enforces that the deleted federation package
// is not imported anywhere. All code moved to peertrust, directoryservice,
// peercompat, outboundsigning, and ocmaux in earlier phases.
func TestNoFederationPackageImports(t *testing.T) {
	bannedImport := "internal/components/federation"

	allowedSubstrings := []string{"/guards/"}

	repoRoot := findRepoRoot(t)
	var violations []string

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
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
		if strings.Contains(string(data), bannedImport) {
			relPath, _ := filepath.Rel(repoRoot, path)
			violations = append(violations, relPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found imports of deleted federation package:\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestNoNonSpecDirectoryServiceJSONTags enforces Appendix C compliance in
// directoryservice models. The spec uses "url" and "displayName", not "domain"
// or "name".
func TestNoNonSpecDirectoryServiceJSONTags(t *testing.T) {
	bannedTags := []string{
		`json:"domain"`, `json:"domain,`,
		`json:"name"`, `json:"name,`,
	}

	repoRoot := findRepoRoot(t)
	dsDir := filepath.Join(repoRoot, "internal", "components", "ocm", "directoryservice")

	if _, err := os.Stat(dsDir); os.IsNotExist(err) {
		t.Skip("directoryservice package not found")
	}

	var violations []string
	err := filepath.WalkDir(dsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		relPath, _ := filepath.Rel(repoRoot, path)

		for _, tag := range bannedTags {
			if strings.Contains(content, tag) {
				violations = append(violations,
					relPath+": non-spec JSON tag "+tag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found non-spec JSON tags in directoryservice (Appendix C uses url and displayName):\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestNoFirstAtOCMAddressParsing enforces that OCM address handling does not
// use first-@ splitting (strings.SplitN with "@" and limit 2). Use the
// address package instead.
func TestNoFirstAtOCMAddressParsing(t *testing.T) {
	pattern := regexp.MustCompile(`SplitN\([^,]*,\s*"@"\s*,\s*2\)`)

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
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		relPath, _ := filepath.Rel(repoRoot, path)

		if locs := pattern.FindAllStringIndex(content, -1); len(locs) > 0 {
			for _, loc := range locs {
				line := 1 + strings.Count(content[:loc[0]], "\n")
				violations = append(violations,
					relPath+":"+itoa(line)+": first-@ address splitting")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("Found first-@ OCM address parsing (use the address package):\n%s",
			strings.Join(violations, "\n"))
	}
}
