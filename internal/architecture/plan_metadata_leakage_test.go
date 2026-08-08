// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

var (
	// Parenthesized coordinates require at least one digit (T7, T7a, F2); bare (T)/(F) are not.
	planCoordParen = regexp.MustCompile(`\([CBFMKFTQPW]\d+[a-zA-Z]*\)|\([CBF]:`)
	planCoordBare  = regexp.MustCompile(`(?i)\b(?:K2 JSON|K2 format|M1 union)\b`)
	planCoordToken = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:Phase\s+)?[CBFMKFTQPW]\d{1,2}[a-zA-Z]*(?:[^a-zA-Z0-9_]|$)`)

	planMetadataPatterns = []*regexp.Regexp{
		planCoordParen,
		planCoordBare,
		planCoordToken,
	}

	ietfLegacyPatterns = []*regexp.Regexp{
		// Appendix mask covers only the IETF/RFC span (e.g. "Appendix C"); adjacent
		// parentheticals such as "(T7a)" stay visible to coordinate matchers.
		regexp.MustCompile(`(?i)appendix\s+[a-z](?:\.[0-9]+(?:\.[0-9]+)?)?`),
		regexp.MustCompile(`(?i)\brfc\s+\d+`),
		regexp.MustCompile(`(?i)\bclass\s+[bc]\b`),
		regexp.MustCompile(`(?i)ietf[-\s]ocm`),
		regexp.MustCompile(`rfc-editor\.org`),
		regexp.MustCompile(`(?i)\bocm appendix\s+[a-z]`),
		regexp.MustCompile(`(?i)github\.com/cs3org/OCM-API`),
	}
)

var planMetadataSelfSkip = map[string]bool{
	"internal/architecture/plan_metadata_leakage_test.go": true,
	"internal/architecture/findaccepted_guard_test.go":    true,
}

func TestPlanMetadata_NoLeaks(t *testing.T) {
	t.Parallel()
	root := modroot.ModuleRoot(t)

	violations, err := scanPlanMetadataLeaks(root)
	if err != nil {
		t.Fatalf("scan plan metadata leaks: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("planning-metadata leak violations:\n%s", strings.Join(violations, "\n"))
	}
}

func TestFindPlanMetadataLeak_PositiveCoordinate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		{name: "paren letter suffix", text: "reason-coded failure (T7a)."},
		{name: "paren bare digits", text: "see (F2) for details"},
		{name: "bare token suffix", text: "covers M1a edge case"},
		{name: "slog-style message", text: "discovery failed (F2b)"},
		{name: "appendix adjacent coordinate", text: "See Appendix C (T7a) for the failure path."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if leak := findPlanMetadataLeak(tc.text); leak == "" {
				t.Fatalf("expected coordinate leak in %q", tc.text)
			}
		})
	}
}

func TestFindPlanMetadataLeak_NegativeLegitimate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
	}{
		{name: "rfc reference", text: "See RFC 9383 for the OCM discovery profile."},
		{name: "ietf appendix", text: "Defined in Appendix A.1 of the IETF OCM draft."},
		{name: "plain appendix", text: "See Appendix C for the discovery profile."},
		{name: "digitless paren T", text: "retry helper (T) after timeout"},
		{name: "digitless paren F", text: "fallback path (F) when upstream is down"},
		{name: "non coordinate token", text: "retry the Class helper after timeout"},
		{name: "plain prose", text: "upstream discovery succeeded without invite dialog"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if leak := findPlanMetadataLeak(tc.text); leak != "" {
				t.Fatalf("expected no leak in %q, got %q", tc.text, leak)
			}
		})
	}
}

func TestScanFilePlanMetadataLeaks_PositiveAndSlog(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.go")

	src := `package sample

import "log/slog"

// helper returns a reason-coded failure (T7a).
func helper(log *slog.Logger) {
	log.InfoContext(nil, "discovery failed (F2b)")
}
`

	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	violations, err := scanFilePlanMetadataLeaks(dir, path)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}

	if len(violations) < 2 {
		t.Fatalf("expected comment and slog/string leaks, got %v", violations)
	}

	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, "T7a") && !strings.Contains(joined, "(T7a)") {
		t.Fatalf("expected paren coordinate in violations: %v", violations)
	}

	if !strings.Contains(joined, "F2b") && !strings.Contains(joined, "(F2b)") {
		t.Fatalf("expected slog/string coordinate in violations: %v", violations)
	}
}

func TestScanFilePlanMetadataLeaks_NegativeRFC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.go")

	src := `package sample

// See RFC 9383 and Appendix A.1 for discovery requirements.
func helper() string {
	return "compat with github.com/cs3org/OCM-API schema"
}
`

	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	violations, err := scanFilePlanMetadataLeaks(dir, path)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}

	if len(violations) != 0 {
		t.Fatalf("expected no leaks for IETF/RFC references, got %v", violations)
	}
}

// scanPlanMetadataLeaks walks the module tree and AST-scans Go sources for
// planning coordinate breadcrumbs in comments and string literals.
func scanPlanMetadataLeaks(root string) ([]string, error) {
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() {
			return skipHeavyDir(d)
		}

		fileViolations, err := scanFilePlanMetadataLeaks(root, path)
		if err != nil {
			return err
		}

		violations = append(violations, fileViolations...)

		return nil
	})
	if err != nil {
		return violations, fmt.Errorf("architecture: check plan metadata: %w", err)
	}

	return violations, nil
}

// scanFilePlanMetadataLeaks parses one Go file and inspects comment nodes and
// string literals for planning-metadata breadcrumbs.
func scanFilePlanMetadataLeaks(root, path string) ([]string, error) {
	if !strings.HasSuffix(path, ".go") {
		return nil, nil
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, fmt.Errorf("architecture: check plan metadata: %w", err)
	}

	rel = filepath.ToSlash(rel)
	if planMetadataSelfSkip[rel] {
		return nil, nil
	}

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil //nolint:nilerr // test: unparseable files are skipped, not walk errors
	}

	violations := collectCommentPlanMetadataLeaks(fset, node, rel)
	violations = append(violations, collectLiteralPlanMetadataLeaks(fset, node, rel)...)

	return violations, nil
}

// collectCommentPlanMetadataLeaks reports planning breadcrumbs in comment nodes.
func collectCommentPlanMetadataLeaks(fset *token.FileSet, node *ast.File, rel string) []string {
	var violations []string

	for _, group := range node.Comments {
		for _, comment := range group.List {
			text := trimCommentText(comment.Text)
			violations = appendPlanMetadataLeak(violations, fset, comment.Pos(), rel, "comment", text)
		}
	}

	return violations
}

// collectLiteralPlanMetadataLeaks reports planning breadcrumbs in string
// literals, including slog and Context-variant call arguments, via one AST path.
func collectLiteralPlanMetadataLeaks(fset *token.FileSet, node *ast.File, rel string) []string {
	var violations []string

	ast.Inspect(node, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		text := strings.Trim(lit.Value, "\"'`")
		violations = appendPlanMetadataLeak(violations, fset, lit.Pos(), rel, "string literal", text)

		return true
	})

	return violations
}

// appendPlanMetadataLeak appends a formatted violation when text contains a
// planning coordinate after IETF/RFC masking.
func appendPlanMetadataLeak(
	violations []string,
	fset *token.FileSet,
	pos token.Pos,
	rel, kind, text string,
) []string {
	leak := findPlanMetadataLeak(text)
	if leak == "" {
		return violations
	}

	line := fset.Position(pos).Line

	return append(violations,
		rel+":"+itoa(line)+": planning-metadata breadcrumb in "+kind+": "+leak)
}

func trimCommentText(raw string) string {
	text := strings.TrimSpace(strings.TrimPrefix(raw, "//"))
	text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))

	return strings.TrimSuffix(text, "*/")
}

// findPlanMetadataLeak reports the first planning coordinate matched in text
// after IETF/RFC legacy spans are masked out.
func findPlanMetadataLeak(text string) string {
	masked := maskIETFLegacy(text)

	for _, pattern := range planMetadataPatterns {
		if match := pattern.FindString(masked); match != "" {
			return strings.TrimSpace(match)
		}
	}

	return ""
}

// maskIETFLegacy blanks IETF/RFC citation spans so legitimate spec references
// are not flagged as planning breadcrumbs.
func maskIETFLegacy(text string) string {
	masked := text

	for _, pattern := range ietfLegacyPatterns {
		masked = pattern.ReplaceAllStringFunc(masked, func(match string) string {
			return strings.Repeat(" ", len(match))
		})
	}

	return masked
}
