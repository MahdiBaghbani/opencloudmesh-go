// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestWireDTOsOnlyInSpec(t *testing.T) {
	wireDTOTypes := []string{
		"NewShareRequest",
		"CreateShareResponse",
		"InviteAcceptedRequest",
		"InviteAcceptedResponse",
		"WebDAVProtocol",
		"OCMErrorResponse",
	}

	patterns := make([]*regexp.Regexp, 0, len(wireDTOTypes))
	for _, name := range wireDTOTypes {
		patterns = append(patterns, regexp.MustCompile(`type\s+`+name+`\s+struct\b`))
	}

	root := modroot.ModuleRoot(t)
	ocmDir := filepath.Join(root, "internal", "components", "ocm")

	if _, err := os.Stat(ocmDir); os.IsNotExist(err) {
		t.Skip("ocm package not found")
	}

	violations, err := scanWireDTOLocations(root, ocmDir, patterns, wireDTOTypes)
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("Wire DTO struct definitions found outside internal/components/ocm/spec/ "+
			"(move them to the spec package):\n%s",
			strings.Join(violations, "\n"))
	}
}

// scanWireDTOLocations walks ocmDir and reports wire DTO struct definitions
// outside the spec/ tree.
func scanWireDTOLocations(root, ocmDir string, patterns []*regexp.Regexp, wireDTOTypes []string) ([]string, error) {
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

		relPath, err := filepath.Rel(ocmDir, path)
		if err != nil {
			return fmt.Errorf("architecture: locate wire dto: %w", err)
		}

		if strings.HasPrefix(filepath.ToSlash(relPath), "spec/") {
			return nil
		}

		fileViolations, err := scanFileForWireDTOs(root, path, patterns, wireDTOTypes)
		if err != nil {
			return err
		}

		violations = append(violations, fileViolations...)

		return nil
	})
	if err != nil {
		return violations, fmt.Errorf("architecture: locate wire dto: %w", err)
	}

	return violations, nil
}

// scanFileForWireDTOs reports wire DTO struct definitions in one Go file.
func scanFileForWireDTOs(root, path string, patterns []*regexp.Regexp, wireDTOTypes []string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("architecture: locate wire dto: %w", err)
	}

	fileRel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, fmt.Errorf("architecture: locate wire dto: %w", err)
	}

	content := string(data)

	var violations []string

	for i, pat := range patterns {
		for _, loc := range pat.FindAllStringIndex(content, -1) {
			line := 1 + strings.Count(content[:loc[0]], "\n")
			violations = append(violations,
				fileRel+":"+itoa(line)+": wire DTO type "+wireDTOTypes[i]+" defined outside spec/")
		}
	}

	return violations, nil
}
