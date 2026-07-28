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
	State           string `json:"state"`
	ReceiverHost    string `json:"receiverHost,omitempty"`
	HasSharedSecret bool   `json:"hasSharedSecret"`
}

// RedactedIncomingShare is a persistence-safe view of one incoming share row.
type RedactedIncomingShare struct {
	ShareID         string `json:"shareId"`
	ProviderID      string `json:"providerId"`
	SendingServer   string `json:"sendingServer,omitempty"`
	State           string `json:"state"`
	UserID          string `json:"userId,omitempty"`
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
	State        string `json:"state"`
}

type rawIncomingShare struct {
	ShareID       string `json:"shareId"`
	ProviderID    string `json:"providerId"`
	SendingServer string `json:"sendingServer"`
	SharedSecret  string `json:"sharedSecret"`
	State         string `json:"state"`
	UserID        string `json:"userId"`
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

func readOutgoingShares(dataDir string) (map[string]RedactedOutgoingShare, error) { //nolint:dupl // intentional: parallel outgoing/incoming share readers share file-read structure but map different persisted types
	path := filepath.Join(dataDir, "data", fileOutgoingShares)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]RedactedOutgoingShare{}, nil
		}

		return nil, fmt.Errorf("read outgoing shares: %w", err)
	}

	var byProvider map[string]rawOutgoingShare
	if err := json.Unmarshal(raw, &byProvider); err != nil {
		return nil, fmt.Errorf("decode outgoing shares: %w", err)
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
			State:           share.State,
			ReceiverHost:    share.ReceiverHost,
			HasSharedSecret: share.SharedSecret != "",
		}
	}

	return out, nil
}

func readIncomingShares(dataDir string) (map[string]RedactedIncomingShare, error) { //nolint:dupl // intentional: parallel outgoing/incoming share readers share file-read structure but map different persisted types
	path := filepath.Join(dataDir, "data", fileIncomingShares)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]RedactedIncomingShare{}, nil
		}

		return nil, fmt.Errorf("read incoming shares: %w", err)
	}

	var byShareID map[string]rawIncomingShare
	if err := json.Unmarshal(raw, &byShareID); err != nil {
		return nil, fmt.Errorf("decode incoming shares: %w", err)
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
			SendingServer:   share.SendingServer,
			State:           share.State,
			UserID:          share.UserID,
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
