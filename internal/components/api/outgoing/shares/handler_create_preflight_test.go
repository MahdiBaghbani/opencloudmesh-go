// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
)

// hostStubResolver returns per-host facts for tests that need instance-level
// override behavior without wiring a real peer-mapping config.
type hostStubResolver struct {
	defaultFacts policy.Facts
	overrides    map[string]policy.Facts
}

func (r *hostStubResolver) ResolveFacts(host string) policy.Facts {
	if facts, ok := r.overrides[host]; ok {
		return facts
	}

	return r.defaultFacts
}

func TestHandleCreate_LegacyVoluntaryNoPeerCriterion_Returns201(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer([]string{}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-voluntary-no-peer-criterion-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one POST, got %d", postCount.Load())
	}

	if captured.Protocol.WebDAV == nil {
		t.Fatal("expected webdav protocol in captured payload")
	}

	if captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected no must-exchange-token requirement for legacy voluntary")
	}
}

func TestHandleCreate_PeerForcedCriteria_EmitsRequirement(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer(
		[]string{"exchange-token"},
		[]string{spec.CriteriaMustExchangeToken},
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	// Use a legacy voluntary code flow so the local facts would not include the
	// requirement on their own. The peer's must-exchange-token criterion should
	// still force it.
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-peer-forced-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one POST, got %d", postCount.Load())
	}

	if captured.Protocol.WebDAV == nil {
		t.Fatal("expected webdav protocol in captured payload")
	}

	if !captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatalf("expected must-exchange-token requirement, got %v", captured.Protocol.WebDAV.Requirements)
	}

	shares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(shares) != 1 {
		t.Fatalf("expected one stored share, got %d", len(shares))
	}

	if len(shares[0].Requirements) != 1 || shares[0].Requirements[0] != spec.RequirementMustExchangeToken {
		t.Fatalf("expected persisted peer-forced share to require must-exchange-token, got %v", shares[0].Requirements)
	}
}

func TestHandleCreate_InstanceOverride_RelaxesOnlyMatchedHost(t *testing.T) {
	matchedSrv, matchedPost, matchedCaptured := makeCapturingReceiverTLSServer([]string{}, []string{})
	defer matchedSrv.Close()

	matchedHost := matchedSrv.Listener.Addr().String()

	otherSrv, otherPost, _ := makeCapturingReceiverTLSServer([]string{}, []string{})
	defer otherSrv.Close()

	otherHost := otherSrv.Listener.Addr().String()

	resolver := &hostStubResolver{
		defaultFacts: policy.NewCodeFlow().Evaluate(),
		overrides: map[string]policy.Facts{
			matchedHost: {
				IncludesTokenExchangeRequirement: false,
			},
		},
	}

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newOutgoingHandler(t, repo, discClient, ctxClient, user, resolver, "")

	// Matched host should be relaxed and create a share to a receiver that does
	// not advertise exchange-token.
	tmpFile := createTempShareFile(t, "outgoing-instance-matched-*")
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(matchedHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("matched host: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if matchedPost.Load() != 1 {
		t.Fatalf("matched host: expected one POST, got %d", matchedPost.Load())
	}

	if matchedCaptured.Protocol.WebDAV == nil {
		t.Fatal("matched host: expected webdav protocol in captured payload")
	}

	if matchedCaptured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("matched host: expected no must-exchange-token requirement")
	}

	// The relaxed matched host creates a share with no forced requirements;
	// the persisted share must have an empty Requirements slice.
	matchedShares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(matchedShares) != 1 {
		t.Fatalf("matched host: expected one stored share, got %d", len(matchedShares))
	}

	if len(matchedShares[0].Requirements) != 0 {
		t.Fatalf("matched host: expected empty persisted requirements, got %v", matchedShares[0].Requirements)
	}

	// Another host without the instance override should remain strict and fail.
	tmpFile2 := createTempShareFile(t, "outgoing-instance-other-*")
	req2 := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(otherHost, tmpFile2)))
	req2.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	handler.HandleCreate(w2, req2)

	if w2.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("other host: expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w2.Code, w2.Body.String())
	}

	if otherPost.Load() != 0 {
		t.Fatalf("other host: expected no remote POST, got %d", otherPost.Load())
	}
}

func TestHandleCreate_LocalSenderMissingTokenEndpoint_NonStrict_Allows(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	resolver := &stubResolver{facts: configfixture.CodeFlowLegacyVoluntary().Evaluate()}
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
		resolver,
		"",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "outgoing-no-local-endpoint-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one POST, got %d", postCount.Load())
	}

	shares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(shares) != 1 {
		t.Fatalf("expected one stored share, got %d", len(shares))
	}

	if len(shares[0].Requirements) != 0 {
		t.Fatalf("expected non-strict share to have empty requirements, got %v", shares[0].Requirements)
	}
}

func TestHandleCreate_PeerForcedCriterion_ReceiverLacksExchangeToken_Rejects(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{}, []string{spec.CriteriaMustExchangeToken})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	// Local facts use the legacy voluntary flow: IncludesTokenExchangeRequirement
	// is false. The peer forces the must-exchange-token criterion, but the
	// receiver does not advertise exchange-token, so create must reject.
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-peer-forced-receiver-lacks-exchange-token-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}
}

func TestHandleCreate_NilResolver_NonStrict_Allows(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()

	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
		nil,
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "outgoing-nil-resolver-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handler panicked with nil resolver: %v", r)
		}
	}()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one remote POST, got %d", postCount.Load())
	}

	shares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(shares) != 1 {
		t.Fatalf("expected one stored share, got %d", len(shares))
	}

	if len(shares[0].Requirements) != 0 {
		t.Fatalf("expected non-strict nil-resolver share to have empty requirements, got %v", shares[0].Requirements)
	}
}

// TestHandleCreate_StrictEmptyOrMissingLocalEndpoint_Rejects covers the strict
// gate: token exchange must be included (peer forces must-exchange-token), but
// the local token endpoint is empty or missing. The create path must reject and
// must not fall back to the legacy shared-secret path.
func TestHandleCreate_StrictEmptyOrMissingLocalEndpoint_Rejects(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{spec.CriteriaMustExchangeToken})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	// Token exchange is required, but the local token endpoint is empty or
	// missing. The create path must reject and must not fall back to the
	// legacy shared-secret path.
	resolver := &stubResolver{facts: policy.Facts{}}
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
		resolver,
		"",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "outgoing-strict-empty-endpoint-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}

	shares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(shares) != 0 {
		t.Fatalf("expected no stored share (no legacy fallback), got %d", len(shares))
	}
}

// TestHandleCreate_StrictPersistsMustExchangeTokenRequirement asserts that a
// strict create persists must-exchange-token in the stored share's
// Requirements, mirroring the wire payload assertion in other strict tests.
func TestHandleCreate_StrictPersistsMustExchangeTokenRequirement(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-strict-persist-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one POST, got %d", postCount.Load())
	}

	shares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(shares) != 1 {
		t.Fatalf("expected one stored share, got %d", len(shares))
	}

	if len(shares[0].Requirements) != 1 || shares[0].Requirements[0] != spec.RequirementMustExchangeToken {
		t.Fatalf("expected persisted strict share to require must-exchange-token, got %v", shares[0].Requirements)
	}
}
