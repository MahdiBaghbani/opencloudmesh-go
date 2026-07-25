package shares_test

import (
	"bytes"
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

func (r *hostStubResolver) ResolveFacts(host string, disc policy.DiscoveryView) policy.Facts {
	if facts, ok := r.overrides[host]; ok {
		return facts
	}
	return r.defaultFacts
}

func TestHandleCreate_LegacyVoluntaryNonCapableReceiver_Returns201(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer([]string{}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-voluntary-non-capable-*")
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
		t.Fatal("expected no must-exchange-token requirement for non-capable receiver")
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
				TokenExchangeCapable:             true,
				IncludesTokenExchangeRequirement: false,
			},
		},
	}

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newOutgoingHandler(t, repo, discClient, ctxClient, user, resolver, "")

	// Matched host should be relaxed and create a share to a non-capable receiver.
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

func TestHandleCreate_LocalSenderNotTokenCapable_Rejects(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	resolver := &stubResolver{facts: policy.Facts{TokenExchangeCapable: false}}
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
		resolver,
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "outgoing-not-capable-*")
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

func TestHandleCreate_LocalSenderMissingTokenEndpoint_Rejects(t *testing.T) {
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

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}
}

func TestHandleCreate_PeerForcedNonCapableReceiver_Rejects(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{}, []string{spec.CriteriaMustExchangeToken})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	// Local facts use the legacy voluntary flow: the sender is capable and the
	// includes-token-exchange requirement is false. The peer forces the
	// criterion, but the receiver does not advertise exchange-token, so the
	// gated capability check must reject.
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-peer-forced-non-capable-*")
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

func TestHandleCreate_NilResolver_FailsClosed(t *testing.T) {
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

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}
}
