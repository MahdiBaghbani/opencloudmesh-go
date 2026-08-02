// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	fileOutgoingShares = "outgoing_shares.json"
	fileIncomingShares = "incoming_shares.json"
)

// RedactedOutgoingShare is a persistence-safe view of one outgoing share row.
type RedactedOutgoingShare struct {
	ProviderID      string `json:"providerId"`
	ShareID         string `json:"shareId,omitempty"`
	WebDAVID        string `json:"webdavId,omitempty"`
	Status          string `json:"status"`
	ReceiverHost    string `json:"receiverHost,omitempty"`
	HasSharedSecret bool   `json:"hasSharedSecret"`
}

// RedactedIncomingShare is a persistence-safe view of one incoming share row.
type RedactedIncomingShare struct {
	ShareID         string `json:"shareId"`
	ProviderID      string `json:"providerId"`
	SenderHost      string `json:"senderHost,omitempty"`
	Status          string `json:"status"`
	RecipientUserID string `json:"recipientUserId,omitempty"`
	HasSharedSecret bool   `json:"hasSharedSecret"`
}

// SharePersistenceSnapshot captures redacted share JSON persistence for stable
// before/after comparisons in negative tests.
type SharePersistenceSnapshot struct {
	Outgoing map[string]RedactedOutgoingShare `json:"outgoing"`
	Incoming map[string]RedactedIncomingShare `json:"incoming"`
}

// TokenPersistenceSnapshot captures redacted token-exchange code presence derived
// from outgoing share sharedSecret fields (there is no separate token JSON file).
type TokenPersistenceSnapshot struct {
	OutgoingCodes map[string]bool `json:"outgoingCodes"`
}

// PersistenceSnapshot combines share and derived token-exchange fingerprints.
type PersistenceSnapshot struct {
	Shares SharePersistenceSnapshot `json:"shares"`
	Tokens TokenPersistenceSnapshot `json:"tokens"`
}

type rawOutgoingShare struct {
	ShareID      string `json:"shareId"`
	ProviderID   string `json:"providerId"`
	WebDAVID     string `json:"webdavId"`
	SharedSecret string `json:"sharedSecret"`
	ReceiverHost string `json:"receiverHost"`
	Status       string `json:"status"`
}

type rawIncomingShare struct {
	ShareID         string `json:"shareId"`
	ProviderID      string `json:"providerId"`
	SenderHost      string `json:"senderHost"`
	SharedSecret    string `json:"sharedSecret"`
	Status          string `json:"status"`
	RecipientUserID string `json:"recipientUserId"`
}

// SnapshotPersistence reads dataDir/data share JSON files and returns redacted
// snapshots suitable for comparison. Missing files yield empty maps.
func SnapshotPersistence(dataDir string) (PersistenceSnapshot, error) {
	shares, err := snapshotShares(dataDir)
	if err != nil {
		return PersistenceSnapshot{}, err
	}

	return PersistenceSnapshot{
		Shares: shares,
		Tokens: tokenSnapshotFromShares(shares.Outgoing),
	}, nil
}

// SnapshotShares reads only the share surfaces from dataDir/data.
func SnapshotShares(dataDir string) (SharePersistenceSnapshot, error) {
	return snapshotShares(dataDir)
}

// SnapshotEqual reports whether two persistence snapshots are identical.
func SnapshotEqual(a, b PersistenceSnapshot) bool {
	ab, err := canonicalSnapshotBytes(a)
	if err != nil {
		return false
	}

	bb, err := canonicalSnapshotBytes(b)
	if err != nil {
		return false
	}

	return bytes.Equal(ab, bb)
}

// CanonicalSnapshotBytes returns deterministic JSON for a snapshot.
func CanonicalSnapshotBytes(s PersistenceSnapshot) ([]byte, error) {
	return canonicalSnapshotBytes(s)
}

func snapshotShares(dataDir string) (SharePersistenceSnapshot, error) {
	outgoing, err := readOutgoingShares(dataDir)
	if err != nil {
		return SharePersistenceSnapshot{}, err
	}

	incoming, err := readIncomingShares(dataDir)
	if err != nil {
		return SharePersistenceSnapshot{}, err
	}

	return SharePersistenceSnapshot{
		Outgoing: outgoing,
		Incoming: incoming,
	}, nil
}

// readShareRows reads one share JSON file from dataDir/data and decodes its
// rows. A missing file yields an empty map.
func readShareRows[Raw any](dataDir, filename, label string) (map[string]Raw, error) {
	path := filepath.Join(dataDir, "data", filename)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]Raw{}, nil
		}

		return nil, fmt.Errorf("read %s shares: %w", label, err)
	}

	var rows map[string]Raw
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("decode %s shares: %w", label, err)
	}

	return rows, nil
}

func readOutgoingShares(dataDir string) (map[string]RedactedOutgoingShare, error) {
	byProvider, err := readShareRows[rawOutgoingShare](dataDir, fileOutgoingShares, "outgoing")
	if err != nil {
		return nil, err
	}

	out := make(map[string]RedactedOutgoingShare, len(byProvider))
	for providerID, share := range byProvider {
		key := providerID
		if key == "" {
			key = share.ProviderID
		}

		out[key] = RedactedOutgoingShare{
			ProviderID:      share.ProviderID,
			ShareID:         share.ShareID,
			WebDAVID:        share.WebDAVID,
			Status:          share.Status,
			ReceiverHost:    share.ReceiverHost,
			HasSharedSecret: share.SharedSecret != "",
		}
	}

	return out, nil
}

func readIncomingShares(dataDir string) (map[string]RedactedIncomingShare, error) {
	byShareID, err := readShareRows[rawIncomingShare](dataDir, fileIncomingShares, "incoming")
	if err != nil {
		return nil, err
	}

	out := make(map[string]RedactedIncomingShare, len(byShareID))
	for shareID, share := range byShareID {
		key := shareID
		if key == "" {
			key = share.ShareID
		}

		out[key] = RedactedIncomingShare{
			ShareID:         share.ShareID,
			ProviderID:      share.ProviderID,
			SenderHost:      share.SenderHost,
			Status:          share.Status,
			RecipientUserID: share.RecipientUserID,
			HasSharedSecret: share.SharedSecret != "",
		}
	}

	return out, nil
}

func tokenSnapshotFromShares(outgoing map[string]RedactedOutgoingShare) TokenPersistenceSnapshot {
	codes := make(map[string]bool, len(outgoing))
	for providerID, share := range outgoing {
		codes[providerID] = share.HasSharedSecret
	}

	return TokenPersistenceSnapshot{OutgoingCodes: codes}
}

func canonicalSnapshotBytes(s PersistenceSnapshot) ([]byte, error) {
	return json.Marshal(s)
}
