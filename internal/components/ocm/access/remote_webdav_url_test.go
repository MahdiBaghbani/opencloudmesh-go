package access

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestBuildWebDAVURL_AbsoluteURIMatchingHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))

	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   "sender.example.com",
		SharedSecret: "secret",
		WebDAVID:     "https://sender.example.com/remote.php/webdav/file.txt",
	}

	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "https://sender.example.com/remote.php/webdav/file.txt"
	if got != want {
		t.Errorf("buildWebDAVURL() = %q, want %q", got, want)
	}
}

func TestBuildWebDAVURL_AbsoluteURIMismatchedHost(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))
	senderHost := discServer.Listener.Addr().String()

	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "https://evil.example.com/webdav/file.txt",
	}

	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "evil.example.com") {
			t.Errorf("expected fallthrough to discovery, but error references evil host: %s", errStr)
		}

		return
	}

	parsed, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("parse discovery-derived URL: %v", parseErr)
	}

	if parsed.Host == "evil.example.com" {
		t.Errorf("expected discovery-derived host, got evil host in URL: %s", got)
	}

	if parsed.Host != senderHost {
		t.Errorf("expected discovery server host in URL, got %q (full URL: %s)", parsed.Host, got)
	}
}

func TestBuildWebDAVURL_AbsoluteURIParseError(t *testing.T) {
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := NewClient(ctxClient, discClient, nil, peerorigin.NewResolver(true))
	senderHost := discServer.Listener.Addr().String()

	disc, err := discClient.Discover(context.Background(), discServer.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	share := &ShareInfo{
		Status:       "accepted",
		SenderHost:   senderHost,
		SharedSecret: "secret",
		WebDAVID:     "://not-a-valid-url",
	}

	got, err := client.buildWebDAVURL(context.Background(), share, "", disc)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "not-a-valid-url") {
			t.Errorf("expected fallthrough to discovery, but error references bad URI: %s", errStr)
		}

		return
	}

	parsed, parseErr := url.Parse(got)
	if parseErr != nil {
		t.Fatalf("parse discovery-derived URL: %v", parseErr)
	}

	if parsed.Host != senderHost {
		t.Errorf("expected discovery server host in URL, got %q (full URL: %s)", parsed.Host, got)
	}
}
