// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// requireRun reloads the run row.
func (e *courierMatrixEnv) requireRun(t *testing.T, runID string) *validatorcore.TestRun {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return run
}

// evidenceRows lists the run's evidence rows for one exact tuple.
func (e *courierMatrixEnv) evidenceRows(
	t *testing.T,
	runID, area, step, reason string,
) []validatorcore.EvidenceRow {
	t.Helper()

	var rows []validatorcore.EvidenceRow
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?", runID, area, step, reason).
		Find(&rows).Error; err != nil {
		t.Fatalf("list evidence rows: %v", err)
	}

	return rows
}

// countEvidence counts every evidence row for the run.
func (e *courierMatrixEnv) countEvidence(t *testing.T, runID string) int {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).
		Model(&validatorcore.EvidenceRow{}).
		Where("test_run_id = ?", runID).
		Count(&count).Error; err != nil {
		t.Fatalf("count evidence: %v", err)
	}

	return int(count)
}

// countStatsRaw counts every stats_raw row in the store.
func (e *courierMatrixEnv) countStatsRaw(t *testing.T) int64 {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).
		Model(&validatorcore.StatsRaw{}).
		Count(&count).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	return count
}

// statsRawForRun loads the single stats_raw row keyed by the run's dedup key.
func (e *courierMatrixEnv) statsRawForRun(t *testing.T, runID string) validatorcore.StatsRaw {
	t.Helper()

	k, err := e.hasher.HashStatsK(runID)
	if err != nil {
		t.Fatalf("HashStatsK: %v", err)
	}

	var rows []validatorcore.StatsRaw
	if err := e.store.DB().WithContext(t.Context()).
		Where("k = ?", k).
		Find(&rows).Error; err != nil {
		t.Fatalf("load stats_raw by k: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("stats_raw rows for run = %d, want 1", len(rows))
	}

	return rows[0]
}

// statsRawForHost lists every stats_raw row for one host hash, oldest first.
func (e *courierMatrixEnv) statsRawForHost(t *testing.T, hostHash string) []validatorcore.StatsRaw {
	t.Helper()

	var rows []validatorcore.StatsRaw
	if err := e.store.DB().WithContext(t.Context()).
		Where("host_hash = ?", hostHash).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		t.Fatalf("list stats_raw for host: %v", err)
	}

	return rows
}

// shareForProvider returns the single stored outgoing share carrying the
// reserved provider id.
func (e *courierMatrixEnv) shareForProvider(t *testing.T, providerID string) *sharesoutgoing.OutgoingShare {
	t.Helper()

	var matches []*sharesoutgoing.OutgoingShare

	for _, share := range e.listShares(t) {
		if share.ProviderID == providerID {
			matches = append(matches, share)
		}
	}

	if len(matches) != 1 {
		t.Fatalf("stored shares with provider id = %d, want 1", len(matches))
	}

	return matches[0]
}

// capturedPayload returns the single captured wire payload carrying the
// reserved provider id.
func (e *courierMatrixEnv) capturedPayload(t *testing.T, providerID string) spec.NewShareRequest {
	t.Helper()

	var matches []spec.NewShareRequest

	for _, payload := range e.captured.all() {
		if payload.ProviderID == providerID {
			matches = append(matches, payload)
		}
	}

	if len(matches) != 1 {
		t.Fatalf("captured payloads with provider id = %d, want 1", len(matches))
	}

	return matches[0]
}

// requireStatsKeysWritten proves every terminal run wrote statistics exactly
// once under its own keyed dedup value, and that the keys are distinct.
func requireStatsKeysWritten(t *testing.T, env *courierMatrixEnv, runs []string) map[string]bool {
	t.Helper()

	ks := map[string]bool{}

	for _, id := range runs {
		run := env.requireRun(t, id)

		if run.StatsWrittenAt == nil {
			t.Fatalf("stats_written_at is nil for run %s", id)
		}

		k, err := env.hasher.HashStatsK(id)
		if err != nil {
			t.Fatalf("HashStatsK(%s): %v", id, err)
		}

		if ks[k] {
			t.Fatalf("duplicate stats key %q", k)
		}

		ks[k] = true

		env.statsRawForRun(t, id)
	}

	if len(ks) != len(runs) {
		t.Fatalf("distinct stats keys = %d, want %d", len(ks), len(runs))
	}

	return ks
}

// requireHostAggregate loads the single aggregate row for the host.
func requireHostAggregate(t *testing.T, env *courierMatrixEnv, hostHash string) validatorcore.StatsAggregate {
	t.Helper()

	var aggregates []validatorcore.StatsAggregate

	if err := env.store.DB().WithContext(t.Context()).
		Where("host_hash = ?", hostHash).
		Find(&aggregates).Error; err != nil {
		t.Fatalf("list aggregates: %v", err)
	}

	if len(aggregates) != 1 {
		t.Fatalf("aggregate rows for host = %d, want 1", len(aggregates))
	}

	return aggregates[0]
}

// requireAggregateMatchesRaw folds the raw rows the way the aggregate builder
// does and proves the persisted aggregate matches the seeded expectations.
func requireAggregateMatchesRaw(
	t *testing.T,
	aggregate validatorcore.StatsAggregate,
	rawRows []validatorcore.StatsRaw,
	wantHealthy int,
) {
	t.Helper()

	if aggregate.TotalSessions != int64(len(rawRows)) {
		t.Fatalf("aggregate total sessions = %d, want %d", aggregate.TotalSessions, len(rawRows))
	}

	healthy := 0

	for _, row := range rawRows {
		if validatorcore.DeriveHealthy(row) {
			healthy++
		}
	}

	if healthy != wantHealthy {
		t.Fatalf("healthy raw rows = %d, want %d", healthy, wantHealthy)
	}

	if aggregate.HealthySessions != int64(healthy) {
		t.Fatalf("aggregate healthy sessions = %d, want %d", aggregate.HealthySessions, healthy)
	}

	var firstSeen, lastSeen int64

	var latest validatorcore.StatsRaw

	for _, row := range rawRows {
		if firstSeen == 0 || row.CreatedAt < firstSeen {
			firstSeen = row.CreatedAt
		}

		if row.CreatedAt >= lastSeen {
			lastSeen = row.CreatedAt
			latest = row
		}
	}

	if aggregate.FirstSeenTS != firstSeen {
		t.Fatalf("aggregate first_seen_ts = %d, want %d", aggregate.FirstSeenTS, firstSeen)
	}

	if aggregate.LastSeenTS != lastSeen {
		t.Fatalf("aggregate last_seen_ts = %d, want %d", aggregate.LastSeenTS, lastSeen)
	}

	if aggregate.LastHealthy != validatorcore.DeriveHealthy(latest) {
		t.Fatalf("aggregate last_healthy = %v, want %v", aggregate.LastHealthy, validatorcore.DeriveHealthy(latest))
	}

	if aggregate.LastPlatform != latest.Platform {
		t.Fatalf("aggregate last_platform = %q, want %q", aggregate.LastPlatform, latest.Platform)
	}
}

// assertPublicStatistics proves the all-time public totals and area buckets.
func assertPublicStatistics(t *testing.T, env *courierMatrixEnv) {
	t.Helper()

	stats, err := env.store.QueryFederationTesterStatistics(
		t.Context(), validatorcore.BuildStatisticsWindow(0, time.Now()))
	if err != nil {
		t.Fatalf("QueryFederationTesterStatistics: %v", err)
	}

	if stats.Totals.Sessions != 3 {
		t.Fatalf("public sessions = %d, want 3", stats.Totals.Sessions)
	}

	if stats.Totals.UniqueHosts != 1 {
		t.Fatalf("public unique hosts = %d, want 1", stats.Totals.UniqueHosts)
	}

	sharingArea := findPublicArea(stats, validatorcore.SpecificationAreaSharing)

	if sharingArea == nil || sharingArea.Pass != 2 || sharingArea.Fail != 1 {
		t.Fatalf("public sharing area = %+v, want pass 2 fail 1", sharingArea)
	}

	capabilityArea := findPublicArea(stats, validatorcore.SpecificationAreaCapability)

	if capabilityArea == nil || capabilityArea.Pass != 2 {
		t.Fatalf("public capability area = %+v, want pass 2", capabilityArea)
	}
}

// assertRaterRawParity proves each assessed rater area grade matches the
// persisted raw grade and the overall grades fold to pass, fail, pass.
func assertRaterRawParity(t *testing.T, env *courierMatrixEnv, runs []string) {
	t.Helper()

	wantOverall := []string{validatorcore.GradePass, validatorcore.GradeFail, validatorcore.GradePass}

	for i, id := range runs {
		run := env.requireRun(t, id)

		score, _, err := env.store.LoadSpecificationRating(t.Context(), run)
		if err != nil {
			t.Fatalf("LoadSpecificationRating(%s): %v", id, err)
		}

		if score.Grade == nil || *score.Grade != wantOverall[i] {
			t.Fatalf("run %d rater grade = %v, want %q", i, score.Grade, wantOverall[i])
		}

		raw := env.statsRawForRun(t, id)

		for _, area := range score.Areas {
			requireRawAreaGrade(t, raw, i, area)
		}
	}
}

// statsRawContainsK reports whether the raw rows carry the keyed dedup value.
func statsRawContainsK(rows []validatorcore.StatsRaw, k string) bool {
	for _, row := range rows {
		if row.K == k {
			return true
		}
	}

	return false
}

// requireAreaScore returns the run's rater score for one area.
func requireAreaScore(
	t *testing.T,
	score validatorcore.SpecificationScore,
	area string,
) validatorcore.SpecificationAreaScore {
	t.Helper()

	for _, candidate := range score.Areas {
		if candidate.Area == area {
			return candidate
		}
	}

	t.Fatalf("area %q not found in rater score", area)

	return validatorcore.SpecificationAreaScore{}
}

// findPublicArea returns the public statistics bucket for one area.
func findPublicArea(
	stats *validatorcore.FederationTesterStatistics,
	area string,
) *validatorcore.StatisticsArea {
	for i := range stats.Areas {
		if stats.Areas[i].Area == area {
			return &stats.Areas[i]
		}
	}

	return nil
}

// rawGradeForArea maps a rater area onto the persisted raw grade column.
func rawGradeForArea(raw validatorcore.StatsRaw, area string) *string {
	switch area {
	case validatorcore.SpecificationAreaDiscovery:
		return raw.GradeDiscovery
	case validatorcore.SpecificationAreaTLS:
		return raw.GradeTLS
	case validatorcore.SpecificationAreaJWKS:
		return raw.GradeJWKS
	case validatorcore.SpecificationAreaHTTPSig:
		return raw.GradeHTTPSig
	case validatorcore.SpecificationAreaSharing:
		return raw.GradeSharing
	case validatorcore.SpecificationAreaNotification:
		return raw.GradeNotification
	case validatorcore.SpecificationAreaToken:
		return raw.GradeToken
	case validatorcore.SpecificationAreaCapability:
		return raw.GradeCapability
	default:
		return nil
	}
}

// requireRawAreaGrade proves the persisted raw grade matches the rater grade
// for one assessed area.
func requireRawAreaGrade(
	t *testing.T,
	raw validatorcore.StatsRaw,
	runIndex int,
	area validatorcore.SpecificationAreaScore,
) {
	t.Helper()

	if area.Grade == nil {
		return
	}

	rawGrade := rawGradeForArea(raw, area.Area)

	if rawGrade == nil || *rawGrade != *area.Grade {
		t.Fatalf("run %d area %q raw grade = %v, want %q", runIndex, area.Area, rawGrade, *area.Grade)
	}
}

// requireParty loads a party that must exist.
func requireParty(t *testing.T, env *courierMatrixEnv, id string) *identity.User {
	t.Helper()

	party, err := env.parties.Get(t.Context(), id)
	if err != nil {
		t.Fatalf("load party %s: %v", id, err)
	}

	return party
}

// requireProbePartyShape proves the probe role, local realm, and absence of
// an expiry on one session party.
func requireProbePartyShape(t *testing.T, party *identity.User) {
	t.Helper()

	if party.Role != identity.RoleProbe {
		t.Fatalf("party %s role = %q, want %q", party.ID, party.Role, identity.RoleProbe)
	}

	if party.Realm != testLocalDomain {
		t.Fatalf("party %s realm = %q, want %q", party.ID, party.Realm, testLocalDomain)
	}

	if party.ExpiresAt != nil {
		t.Fatalf("party %s expires_at = %v, want nil", party.ID, party.ExpiresAt)
	}
}

// requireUUIDv7 asserts the id parses as a version-7 UUID.
func requireUUIDv7(t *testing.T, id string) {
	t.Helper()

	parsed, err := uuid.Parse(id)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("id %q is not a UUIDv7 (err=%v)", id, err)
	}
}

// matrixShareID mints a share row id.
func matrixShareID(t *testing.T) string {
	t.Helper()

	id, err := identity.UUIDv7()
	if err != nil {
		t.Fatalf("mint share id: %v", err)
	}

	return id
}

// matrixInviteToken mints a peer invite token with the production token shape.
func matrixInviteToken(t *testing.T) string {
	t.Helper()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("mint invite token: %v", err)
	}

	return hex.EncodeToString(b)
}
