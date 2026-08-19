// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package statistics

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	redactSigContextPrefix    = "redact-sig|"
	statsHostContextPrefix    = "stats-host|"
	statsSessionContextPrefix = "stats-session|"
)

// HashRedactSig returns a keyed BLAKE3 digest for evidence redaction using the
// context string redact-sig|<value>.
func HashRedactSig(salt, value []byte) ([]byte, error) {
	if len(salt) != RedactionSaltSize {
		return nil, fmt.Errorf("statistics: redact-sig salt must be %d bytes", RedactionSaltSize)
	}

	h, err := blake3.NewKeyed(salt)
	if err != nil {
		return nil, fmt.Errorf("statistics: redact-sig keyed hasher: %w", err)
	}

	context := redactSigContextPrefix + string(value)
	if _, err := h.WriteString(context); err != nil {
		return nil, fmt.Errorf("statistics: redact-sig context: %w", err)
	}

	return h.Sum(nil), nil
}

// HashStatsHost returns a keyed BLAKE3 digest hex string for statistics host
// hashing using the context string stats-host|<lowercase_host>.
func HashStatsHost(salt []byte, host string) (string, error) {
	if len(salt) != RedactionSaltSize {
		return "", fmt.Errorf("statistics: stats-host salt must be %d bytes", RedactionSaltSize)
	}

	normalized := strings.ToLower(strings.TrimSpace(host))
	context := statsHostContextPrefix + normalized

	h, err := blake3.NewKeyed(salt)
	if err != nil {
		return "", fmt.Errorf("statistics: stats-host keyed hasher: %w", err)
	}

	if _, err := h.WriteString(context); err != nil {
		return "", fmt.Errorf("statistics: stats-host context: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashStatsK returns a keyed BLAKE3 digest hex string for a stats_raw row dedup
// key using the context string stats-session|<test_run_id>.
func HashStatsK(salt []byte, value string) (string, error) {
	if len(salt) != RedactionSaltSize {
		return "", fmt.Errorf("statistics: stats-session salt must be %d bytes", RedactionSaltSize)
	}

	h, err := blake3.NewKeyed(salt)
	if err != nil {
		return "", fmt.Errorf("statistics: stats-session keyed hasher: %w", err)
	}

	if _, err := h.WriteString(statsSessionContextPrefix + value); err != nil {
		return "", fmt.Errorf("statistics: stats-session context: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
