// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package memcore is the private shared in-memory persistence engine used by
// the memory driver. It mirrors the JSON driver's in-memory semantics (key
// formats, secondary indexes, clone-on-get) with all disk I/O stripped.
package memcore

import (
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// Core holds the in-memory state for all four persistence surfaces and
// provides their full CRUD layer. Lifecycle: NewCore -> CRUD -> Close.
type Core struct {
	mu     sync.RWMutex
	closed bool

	outgoingShares  map[string]*store.OutgoingShare  // keyed by providerID
	incomingShares  map[string]*store.IncomingShare  // keyed by shareID
	outgoingInvites map[string]*store.OutgoingInvite // keyed by id
	incomingInvites map[string]*store.IncomingInvite // keyed by id

	// Secondary indexes for outgoing shares
	webdavIndex  map[string]string // webdavID -> providerID
	shareIDIndex map[string]string // shareID -> providerID
	secretIndex  map[string]string // sharedSecret -> providerID

	// Secondary index for incoming shares
	providerIndex map[string]string // "sendingServer:providerID" -> shareID

	// Secondary indexes for invites
	outgoingInviteTokenIndex     map[string]string // token -> outgoing invite id
	incomingInviteTokenUserIndex map[string]string // "token\x00recipientUserID" -> incoming invite id
}

// NewCore returns a ready in-memory core with all maps and indexes allocated.
func NewCore() *Core {
	return &Core{
		outgoingShares:               make(map[string]*store.OutgoingShare),
		incomingShares:               make(map[string]*store.IncomingShare),
		outgoingInvites:              make(map[string]*store.OutgoingInvite),
		incomingInvites:              make(map[string]*store.IncomingInvite),
		webdavIndex:                  make(map[string]string),
		shareIDIndex:                 make(map[string]string),
		secretIndex:                  make(map[string]string),
		providerIndex:                make(map[string]string),
		outgoingInviteTokenIndex:     make(map[string]string),
		incomingInviteTokenUserIndex: make(map[string]string),
	}
}

// Close marks the core closed; later operations fail with store.ErrClosed.
// Safe to call on a nil Core.
func (c *Core) Close() error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true

	return nil
}

// Compile-time interface checks.
var _ store.OutgoingShareStore = (*Core)(nil)
var _ store.IncomingShareStore = (*Core)(nil)
var _ store.OutgoingInviteStore = (*Core)(nil)
var _ store.IncomingInviteStore = (*Core)(nil)
