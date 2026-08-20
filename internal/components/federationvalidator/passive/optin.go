// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const codeOptInCreateOnly = "opt_in_create_only"

var errNullOptIn = errors.New("opt-in field must be a JSON boolean")

type startRequest struct {
	Target         string `json:"target"`
	ID             string `json:"id"`
	OptInStats     *bool  `json:"optInStats"`
	OptInPermanent *bool  `json:"optInPermanent"`
}

type sessionOptIn struct {
	Stats     bool
	Permanent bool
	Channel   string
}

func decodeStartRequest(body []byte) (startRequest, error) {
	var req startRequest

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		return startRequest{}, fmt.Errorf("decode start request: %w", err)
	}

	if err := rejectNullOptIn(body); err != nil {
		return startRequest{}, err
	}

	return req, nil
}

func rejectNullOptIn(body []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("inspect start request: %w", err)
	}

	for _, key := range []string{"optInStats", "optInPermanent"} {
		val, ok := raw[key]
		if !ok {
			continue
		}

		if strings.TrimSpace(string(val)) == "null" {
			return errNullOptIn
		}
	}

	return nil
}

func optInKeysPresent(req startRequest) bool {
	return req.OptInStats != nil || req.OptInPermanent != nil
}

func startConsent(req startRequest, channel string) sessionOptIn {
	opt := sessionOptIn{Channel: channel}
	if req.OptInStats != nil {
		opt.Stats = *req.OptInStats
	}

	if req.OptInPermanent != nil {
		opt.Permanent = *req.OptInPermanent
	}

	return opt
}

func applyCreateConsent(row *validatorcore.TestRun, opt sessionOptIn, now int64) {
	if row == nil {
		return
	}

	if opt.Stats {
		statsChannel := opt.Channel
		statsAt := now
		row.OptInStats = true
		row.OptInStatsChannel = &statsChannel
		row.OptInStatsAt = &statsAt
	}

	if opt.Permanent {
		permanentChannel := opt.Channel
		permanentAt := now
		row.OptInPermanent = true
		row.OptInPermanentChannel = &permanentChannel
		row.OptInPermanentAt = &permanentAt
	}
}
