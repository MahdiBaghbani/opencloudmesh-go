package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoAdHocPeerOriginSchemeInApprovedCallSites(t *testing.T) {
	root := modroot.ModuleRoot(t)
	targets := []string{
		"internal/components/ocm/access/remote.go",
		"internal/components/ocm/discovery/peer_adapter.go",
		"internal/components/ocm/shares/incoming/handler.go",
		"internal/components/api/outgoing/shares/handler.go",
		"internal/components/api/inbox/invites/handler.go",
	}

	var violations []string
	for _, relPath := range targets {
		fullPath := filepath.Join(root, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("read %s failed: %v", relPath, err)
		}
		content := string(data)
		if strings.Contains(content, `"://"`) ||
			strings.Contains(content, `"https://"`) ||
			strings.Contains(content, `"http://"`) {
			violations = append(violations, relPath)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("found ad hoc scheme assembly in peer-origin call sites:\n%s", strings.Join(violations, "\n"))
	}
}
