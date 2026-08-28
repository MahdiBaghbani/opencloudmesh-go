// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type cancelOnFetchFetcher struct {
	result *discovery.FetchResult
	err    error
	cancel context.CancelFunc
	calls  int
}

func (s *cancelOnFetchFetcher) FetchFresh(_ context.Context, _ string) (*discovery.FetchResult, error) {
	s.calls++
	if s.calls == 1 && s.cancel != nil {
		s.cancel()
	}

	return s.result, s.err
}

func writeJWKSBody(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	if _, err := io.WriteString(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"YQ"}]}`); err != nil {
		t.Errorf("write jwks body: %v", err)
	}
}

func assertRatedAreaGrade(t *testing.T, store *validatorcore.Core, runID, area, want string) {
	t.Helper()

	run := mustGetRun(t, store, runID)

	score, _, err := store.LoadSpecificationRating(t.Context(), run)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	for _, item := range score.Areas {
		if item.Area != area {
			continue
		}

		if item.Grade == nil || *item.Grade != want {
			t.Fatalf("%s rated grade = %v, want %q", area, item.Grade, want)
		}

		return
	}

	t.Fatalf("area %q missing from specification rating", area)
}

func assertStatsJWKSGrade(t *testing.T, store *validatorcore.Core, want string) {
	t.Helper()

	var raw validatorcore.StatsRaw
	if err := store.DB().WithContext(t.Context()).
		Where("host_hash != ''").
		First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeJWKS == nil || *raw.GradeJWKS != want {
		t.Fatalf("stats grade_jwks = %v, want %q", raw.GradeJWKS, want)
	}
}

func assertHTTPSigTamperedPersisted(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	var n int64
	if err := store.DB().WithContext(t.Context()).
		Model(&validatorcore.ReportExchange{}).
		Where("test_run_id = ? AND request_id LIKE ?", runID, requestIDHTTPSigTampered+"%").
		Count(&n).Error; err != nil {
		t.Fatalf("count tampered httpsig exchanges: %v", err)
	}

	if n < 2 {
		t.Fatalf("tampered httpsig exchanges = %d, want at least 2", n)
	}
}

func advertisedFailingJWKSResult() *discovery.FetchResult {
	result := passingDiscoveryResult(validTLSState())
	result.Discovery.JwksUri = "https://peer.example/jwks.json"
	result.Discovery.Capabilities = []string{spec.CapabilityHTTPSig}

	return result
}
