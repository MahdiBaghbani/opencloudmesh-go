// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

// testInviteAcceptedPoster adapts outbound.Poster to the domain
// InviteAcceptedPoster port for handler tests, mirroring the services/api
// adapter wiring.
type testInviteAcceptedPoster struct {
	poster *outbound.Poster
}

func (p *testInviteAcceptedPoster) PostInviteAccepted(ctx context.Context, targetHost string, body []byte) (*http.Response, error) {
	return p.poster.Send(ctx, outbound.Request{
		TargetHost:   targetHost,
		EndpointPath: "invite-accepted",
		Kind:         outbound.EndpointInvites,
		Body:         body,
	})
}

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	userAID          = "user-a-uuid"
	userBID          = "user-b-uuid"
	testPublicOrigin = "https://localhost:9200"
)

func currentUserFunc(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(_ context.Context) (*identity.User, error) {
		if user == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}

		return user, nil
	}
}

// newTestRouter mounts the inbox invites handler; nil poster suffices for list/import/decline (accept needs outbound).
func newTestRouter(t *testing.T, repo invitesincoming.IncomingInviteRepo, user *identity.User) http.Handler {
	t.Helper()
	return newTestRouterWithDeps(t, repo, user, nil, nil)
}

func newTestRouterWithDeps(
	t *testing.T,
	repo invitesincoming.IncomingInviteRepo,
	user *identity.User,
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
) http.Handler {
	t.Helper()
	localIdentity := tslocalid.MustTestIdentity(t, testPublicOrigin, "")

	var poster invitesincoming.InviteAcceptedPoster
	if httpClient != nil {
		poster = &testInviteAcceptedPoster{poster: outbound.NewPoster(httpClient, discoveryClient, nil, nil)}
	}

	h := inboxinvites.NewHandler(
		repo,
		poster,
		localIdentity.ProviderDomain,
		localIdentity.Scheme,
		currentUserFunc(user),
		testLogger,
	)
	r := chi.NewRouter()
	r.Route("/inbox/invites", func(r chi.Router) {
		r.Get("/", h.HandleList)
		r.Post("/import", h.HandleImport)
		r.Post("/{inviteId}/accept", h.HandleAccept)
		r.Post("/{inviteId}/decline", h.HandleDecline)
	})

	return r
}

func newTestOutboundClients(t *testing.T) (httpclient.HTTPClient, *discovery.Client) {
	t.Helper()

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		InsecureSkipVerify: true,
		MaxResponseBytes:   1 << 20,
	}
	requestClient := httpclient.NewContextClient(httpclient.New(outboundCfg, nil))
	discoveryClient := discovery.NewClient(httpclient.New(outboundCfg, nil), nil)

	return requestClient, discoveryClient
}

func startInviteSenderServer(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	inviteAcceptedCalls := &atomic.Int32{}
	sawSignature := &atomic.Int32{}

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(spec.Discovery{ //nolint:errcheck // test mock handler: JSON encode
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token", "http-sig"},
				TokenEndPoint: srv.URL + "/ocm/token",
			})
		case "/ocm/invite-accepted":
			inviteAcceptedCalls.Add(1)

			if r.Header.Get("Signature") != "" {
				sawSignature.Store(1)
			}

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"ok"}`)) //nolint:errcheck // test mock handler: response write
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, inviteAcceptedCalls, sawSignature
}

func createInviteForUser(repo *invitesincoming.MemoryIncomingInviteRepo, recipientUserID, token, senderFQDN string) *invitesincoming.IncomingInvite {
	invite := &invitesincoming.IncomingInvite{
		Token:           token,
		SenderFQDN:      senderFQDN,
		RecipientUserID: recipientUserID,
		Status:          invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite) //nolint:errcheck // test fixture seed without testing.T

	return invite
}

func buildInviteString(token string) string {
	inner := token + "@" + "remote.example.com"
	return base64.StdEncoding.EncodeToString([]byte(inner))
}
