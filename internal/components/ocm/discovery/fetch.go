// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// FetchResult holds a cache-bypassing discovery fetch with connection metadata.
type FetchResult struct {
	Discovery *spec.Discovery
	Raw       []byte
	Headers   http.Header
	TLS       *tls.ConnectionState
	ServerIP  string
	FetchErr  error
}

// FetchFresh performs a single uncached GET of /.well-known/ocm and returns
// normalized discovery plus response metadata. Discover cache behavior is
// unchanged; callers that need caching must use Discover.
func (c *Client) FetchFresh(ctx context.Context, baseURL string) (*FetchResult, error) {
	if c == nil || c.httpClient == nil {
		return nil, ErrDiscoveryDisabled
	}

	baseURL = strings.TrimSuffix(baseURL, "/")

	result, err := c.fetchDiscoveryFresh(ctx, baseURL+"/.well-known/ocm")
	if err != nil {
		if result == nil {
			return nil, err
		}

		return result, err
	}

	return result, nil
}

func (c *Client) fetchDiscoveryFresh(ctx context.Context, discoveryURL string) (*FetchResult, error) {
	//nolint:bodyclose // readDiscoveryResponseBody closes the response body when present
	resp, meta, getErr := c.httpClient.GetWithConnMeta(ctx, discoveryURL)

	result := &FetchResult{
		ServerIP: meta.ServerIP,
	}

	if resp != nil {
		result.Headers = cloneResponseHeaders(resp.Header)
		result.TLS = resp.TLS
	}

	var data []byte

	if resp != nil && resp.Body != nil {
		var readErr error

		data, readErr = readDiscoveryResponseBody(c.httpClient, resp)
		if readErr != nil {
			return finishFetchResult(result, fmt.Errorf("ocm: fetch discovery document: %w", readErr))
		}

		result.Raw = data
	}

	if getErr != nil {
		return finishFetchResult(result, fmt.Errorf("ocm: fetch discovery document: %w", getErr))
	}

	if resp == nil {
		return finishFetchResult(result, errors.New("ocm: fetch discovery document: missing response"))
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return finishFetchResult(
				result,
				fmt.Errorf("discovery returned status %d: %w", resp.StatusCode, ErrDiscoveryNotFound),
			)
		}

		return finishFetchResult(result, fmt.Errorf("discovery returned status %d", resp.StatusCode))
	}

	disc, err := c.normalizeDiscovery(data, discoveryOriginFromURL(discoveryURL), true)
	if err != nil {
		return finishFetchResult(result, fmt.Errorf("%w: %w", ErrInvalidDiscoveryJSON, err))
	}

	if !disc.Enabled {
		return finishFetchResult(result, fmt.Errorf("%w at %s", ErrOCMDisabled, discoveryURL))
	}

	result.Discovery = &disc

	return result, nil
}

func finishFetchResult(result *FetchResult, err error) (*FetchResult, error) {
	if result != nil {
		result.FetchErr = err
	}

	return result, err
}

func cloneResponseHeaders(headers http.Header) http.Header {
	if headers == nil {
		return http.Header{}
	}

	return headers.Clone()
}

func readDiscoveryResponseBody(client *httpclient.Client, resp *http.Response) ([]byte, error) {
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	maxBytes := client.MaxResponseBytes()
	limitedReader := io.LimitReader(resp.Body, maxBytes+1)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("http: read response body: %w", err)
	}

	if int64(len(body)) > maxBytes {
		return nil, httpclient.ErrResponseTooLarge
	}

	return body, nil
}
