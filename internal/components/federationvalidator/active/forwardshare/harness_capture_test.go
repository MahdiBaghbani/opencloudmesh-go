// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"errors"
	"reflect"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// capturedShares emulates the receiver's provider-keyed share table: the
// first POST with a provider ID creates the row, a repeat with an identical
// payload is an idempotent success, and a repeat with a different payload is
// a conflict.
type capturedShares struct {
	mu       sync.Mutex
	payloads map[string]spec.NewShareRequest
	// entered signals once the receiver accepted a payload, so a test can
	// cancel the client request at the exact post-delivery point.
	entered chan struct{}
	once    sync.Once
}

func newCapturedShares() *capturedShares {
	return &capturedShares{
		payloads: map[string]spec.NewShareRequest{},
		entered:  make(chan struct{}),
	}
}

// record returns true when the payload created a new remote row, false when
// it matched the stored row idempotently, and an error on a payload conflict.
func (c *capturedShares) record(p spec.NewShareRequest) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	existing, ok := c.payloads[p.ProviderID]
	if !ok {
		c.payloads[p.ProviderID] = p
		c.once.Do(func() { close(c.entered) })

		return true, nil
	}

	if !reflect.DeepEqual(existing, p) {
		return false, errors.New("duplicate provider id with different payload")
	}

	return false, nil
}

func (c *capturedShares) all() []spec.NewShareRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]spec.NewShareRequest, 0, len(c.payloads))
	for _, p := range c.payloads {
		out = append(out, p)
	}

	return out
}
