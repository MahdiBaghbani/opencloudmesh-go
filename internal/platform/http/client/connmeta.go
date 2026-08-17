// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
)

// ConnMeta holds connection metadata captured from the actual outbound dial.
type ConnMeta struct {
	ServerIP string
}

// GetWithConnMeta performs a GET and records the remote IP from GotConn.
func (c *Client) GetWithConnMeta(ctx context.Context, urlStr string) (*http.Response, ConnMeta, error) {
	var meta ConnMeta

	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}

			meta.ServerIP = remoteIPFromAddr(info.Conn.RemoteAddr())
		},
	}

	ctx = httptrace.WithClientTrace(ctx, trace)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		//nolint:errorlint // inner err intentionally formatted with %v (not wrapped) to keep it out of the error chain; outer sentinel wrapped via %w
		return nil, ConnMeta{}, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	resp, err := c.DoWithOptions(req, RequestOptions{IsSigned: false})
	if err != nil {
		return resp, meta, err
	}

	return resp, meta, nil
}

// GetJSONWithConnMeta performs a GET, reads the body with size limits, and
// records the remote IP from the connection used for the request.
func (c *Client) GetJSONWithConnMeta(ctx context.Context, urlStr string) ([]byte, *http.Response, ConnMeta, error) {
	resp, meta, err := c.GetWithConnMeta(ctx, urlStr)
	if err != nil {
		return nil, resp, meta, err
	}

	body, readErr := readLimitedResponseBody(c, resp)
	if readErr != nil {
		return nil, resp, meta, readErr
	}

	return body, resp, meta, nil
}

func readLimitedResponseBody(c *Client, resp *http.Response) ([]byte, error) {
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	limitedReader := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("http: read response body: %w", err)
	}

	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}

	return body, nil
}

func remoteIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}

	return host
}
