package access_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// newTestDiscoveryServer returns an httptest.Server that serves a minimal
// discovery document pointing WebDAV at /webdav/ocm/<id>.
func newTestDiscoveryServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := discovery.Discovery{
				Enabled:    true,
				APIVersion: "1.2.2",
				EndPoint:   "https://" + r.Host + "/ocm",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  map[string]string{"webdav": "/webdav/ocm"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(disc)
			return
		}
		http.NotFound(w, r)
	}))
}

// newTestClients creates a discovery client and context client pointed at the test server.
func newTestClients(serverURL string) (*discovery.Client, *httpclient.ContextClient) {
	cfg := &config.OutboundHTTPConfig{
		SSRFMode:         "off",
		TimeoutMS:        5000,
		ConnectTimeoutMS: 2000,
		MaxRedirects:     1,
		MaxResponseBytes: 1048576,
	}
	rawClient := httpclient.New(cfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	ctxClient := httpclient.NewContextClient(rawClient)
	return discClient, ctxClient
}

func TestBuildWebDAVURL_AbsoluteURIMatchingHost(t *testing.T) {
	// When absolute URI host matches sender, the absolute URI is used directly.
	// No discovery call needed, so we pass a nil-safe discovery server.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil)

	// Create a share with matching absolute URI
	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        "sender.example.com",
		SharedSecret:      "secret",
		WebDAVID:          "relative-id",
		WebDAVURIAbsolute: "https://sender.example.com/remote.php/webdav/file.txt",
		MustExchangeToken: false,
	}

	// We test via Access(), which internally calls buildWebDAVURL.
	// The request will fail at the HTTP level (fake host), but we can
	// verify the URL by intercepting. Instead, test the URL derivation
	// indirectly by checking the request goes to the absolute URI.
	//
	// Since we can't easily intercept the final URL without a real server,
	// we test that Access() attempts to reach the absolute URI host, not the
	// discovery server. The error message from the HTTP client will tell us
	// which host it tried to reach.
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// Expect a network error (can't reach sender.example.com), which proves
	// it used the absolute URI, not discovery.
	if err == nil {
		t.Fatal("expected error (unreachable host), got nil")
	}
	// The error should reference the absolute URI host, not the test server
	errStr := err.Error()
	if !containsStr(errStr, "sender.example.com") {
		t.Errorf("expected error to reference sender.example.com, got: %s", errStr)
	}
}

func TestBuildWebDAVURL_AbsoluteURIMismatchedHost(t *testing.T) {
	// When absolute URI host doesn't match sender, fall through to discovery.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil)

	// Sender is the test server (discovery works), but absolute URI points elsewhere
	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        discServer.Listener.Addr().String(),
		SharedSecret:      "secret",
		WebDAVID:          "file-id-123",
		WebDAVURIAbsolute: "https://evil.example.com/webdav/file.txt",
		MustExchangeToken: false,
	}

	// Access will fall through to discovery (test server) and build the URL
	// from the discovery document. The final request will go to the test server's
	// host (from the discovery EndPoint), not evil.example.com.
	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// We expect some error (the WebDAV endpoint doesn't really exist on the test server),
	// but it should NOT reference evil.example.com.
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "evil.example.com") {
			t.Errorf("expected fallthrough to discovery, but error references evil host: %s", errStr)
		}
	}
	// If err == nil, discovery worked and it reached the test server (also correct).
}

func TestBuildWebDAVURL_AbsoluteURIParseError(t *testing.T) {
	// When absolute URI is unparseable, fall through to discovery.
	discServer := newTestDiscoveryServer()
	defer discServer.Close()

	discClient, ctxClient := newTestClients(discServer.URL)
	client := access.NewClient(ctxClient, discClient, nil)

	share := &access.ShareInfo{
		Status:            "accepted",
		SenderHost:        discServer.Listener.Addr().String(),
		SharedSecret:      "secret",
		WebDAVID:          "file-id-456",
		WebDAVURIAbsolute: "://not-a-valid-url",
		MustExchangeToken: false,
	}

	_, err := client.Access(context.Background(), access.AccessOptions{
		Share:   share,
		Method:  "GET",
		SubPath: "",
	})
	// Should have fallen through to discovery, not panicked or used the bad URI.
	if err != nil {
		errStr := err.Error()
		if containsStr(errStr, "not-a-valid-url") {
			t.Errorf("expected fallthrough to discovery, but error references bad URI: %s", errStr)
		}
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
