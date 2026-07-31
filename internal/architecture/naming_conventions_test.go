// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoBannedDSAbbreviations(t *testing.T) {
	standaloneDS := regexp.MustCompile(`\bDS\b`)
	bannedTerms := []string{
		"dsClient", "dsURL", "ds_url",
		"DSMember", "refreshTimeoutPerDS", "dsCount",
	}

	allowedSubstrings := []string{"/architecture/"}

	root := modroot.ModuleRoot(t)

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

		p := filepath.ToSlash(path)
		for _, allow := range allowedSubstrings {
			if strings.Contains(p, allow) {
				return nil
			}
		}

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return err
		}

		content := string(data)

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

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

func TestNoNonSpecDirectoryServiceJSONTags(t *testing.T) {
	bannedTags := []string{
		`json:"domain"`, `json:"domain,`,
		`json:"name"`, `json:"name,`,
	}

	root := modroot.ModuleRoot(t)
	dsDir := filepath.Join(root, "internal", "components", "ocm", "directoryservice")

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

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return err
		}

		content := string(data)

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

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
		t.Fatalf("Found non-spec JSON tags in directoryservice (OCM Appendix C, https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#appendix-c-directory-service, uses url and displayName):\n%s",
			strings.Join(violations, "\n"))
	}
}

func TestNoFirstAtOCMAddressParsing(t *testing.T) {
	pattern := regexp.MustCompile(`SplitN\([^,]*,\s*"@"\s*,\s*2\)`)

	root := modroot.ModuleRoot(t)
	ocmDir := filepath.Join(root, "internal", "components", "ocm")

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

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return err
		}

		content := string(data)

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

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
