// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package outgoing provides outgoing share models and repository.
package outgoing

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// OutgoingShare holds a share created locally for a remote receiver.
type OutgoingShare struct {
	ShareID          string `json:"shareId"`
	ProviderID       string `json:"providerId"`
	WebDAVID         string `json:"webdavId"`
	SharedSecret     string `json:"-"`
	LocalPath        string `json:"localPath"`
	ReceiverHost     string `json:"receiverHost"`
	ReceiverEndPoint string `json:"receiverEndPoint"`
	ShareWith        string `json:"shareWith"`

	Name         string                     `json:"name"`
	ResourceType string                     `json:"resourceType"`
	ShareType    string                     `json:"shareType"`
	Permissions  []string                   `json:"permissions"`
	Owner        string                     `json:"owner"`
	Sender       string                     `json:"sender"`
	Status       shares.OutgoingShareStatus `json:"status"`
	CreatedAt    time.Time                  `json:"createdAt"`
	SentAt       *time.Time                 `json:"sentAt,omitempty"`
	Error        string                     `json:"error,omitempty"`
	Requirements []string                   `json:"requirements,omitempty"`
}

// OutgoingShareRequest carries the body for creating an outgoing share.
type OutgoingShareRequest struct {
	ReceiverDomain string   `json:"receiverDomain"`
	ShareWith      string   `json:"shareWith"`
	LocalPath      string   `json:"localPath"`
	Name           string   `json:"name,omitempty"`
	Permissions    []string `json:"permissions"`
	ResourceType   string   `json:"resourceType,omitempty"`
}
