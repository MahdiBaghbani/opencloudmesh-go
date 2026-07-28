package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func runSameHostRelativeRedirectTest(
	t *testing.T,
	targetBody string,
	getFailMsg string,
	requestCountFailMsg string,
) {
	t.Helper()

	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}

		if r.URL.Path == "/target" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(targetBody)) //nolint:errcheck // test handler response write

			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("%s: %v", getFailMsg, err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("%s, got %d", requestCountFailMsg, requestCount)
	}
}
