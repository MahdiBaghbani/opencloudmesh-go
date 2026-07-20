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
	ProviderID      string `json:"provider_id"`
	ShareID         string `json:"share_id,omitempty"`
	WebDAVID        string `json:"webdav_id,omitempty"`
	State           string `json:"state"`
	ReceiverHost    string `json:"receiver_host,omitempty"`
	HasSharedSecret bool   `json:"has_shared_secret"`
}

// RedactedIncomingShare is a persistence-safe view of one incoming share row.
type RedactedIncomingShare struct {
	ShareID         string `json:"share_id"`
	ProviderID      string `json:"provider_id"`
	SendingServer   string `json:"sending_server,omitempty"`
	State           string `json:"state"`
	UserID          string `json:"user_id,omitempty"`
	HasSharedSecret bool   `json:"has_shared_secret"`
}

// SharePersistenceSnapshot captures redacted share JSON persistence for stable
// before/after comparisons in negative tests.
type SharePersistenceSnapshot struct {
	Outgoing map[string]RedactedOutgoingShare `json:"outgoing"`
	Incoming map[string]RedactedIncomingShare `json:"incoming"`
}

// TokenPersistenceSnapshot captures redacted token-exchange code presence derived
// from outgoing share shared_secret fields (there is no separate token JSON file).
type TokenPersistenceSnapshot struct {
	OutgoingCodes map[string]bool `json:"outgoing_codes"`
}

// PersistenceSnapshot combines share and derived token-exchange fingerprints.
type PersistenceSnapshot struct {
	Shares SharePersistenceSnapshot `json:"shares"`
	Tokens TokenPersistenceSnapshot `json:"tokens"`
}

type rawOutgoingShare struct {
	ShareID      string `json:"share_id"`
	ProviderID   string `json:"provider_id"`
	WebDAVID     string `json:"webdav_id"`
	SharedSecret string `json:"shared_secret"`
	ReceiverHost string `json:"receiver_host"`
	State        string `json:"state"`
}

type rawIncomingShare struct {
	ShareID       string `json:"share_id"`
	ProviderID    string `json:"provider_id"`
	SendingServer string `json:"sending_server"`
	SharedSecret  string `json:"shared_secret"`
	State         string `json:"state"`
	UserID        string `json:"user_id"`
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

func readOutgoingShares(dataDir string) (map[string]RedactedOutgoingShare, error) {
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

func readIncomingShares(dataDir string) (map[string]RedactedIncomingShare, error) {
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
