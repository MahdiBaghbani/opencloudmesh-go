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
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	userAID          = "user-a-uuid"
	userBID          = "user-b-uuid"
	testPublicOrigin = "https://localhost:9200"
)

func currentUserFunc(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		if user == nil {
			return nil, fmt.Errorf("no authenticated user in context")
		}
		return user, nil
	}
}

// newTestRouter mounts the inbox invites handler; nil clients suffice for list/import/decline (accept needs outbound).
func newTestRouter(t *testing.T, repo invitesinbox.IncomingInviteRepo, user *identity.User) http.Handler {
	t.Helper()
	return newTestRouterWithDeps(t, repo, user, nil, nil, nil)
}

func newTestRouterWithDeps(
	t *testing.T,
	repo invitesinbox.IncomingInviteRepo,
	user *identity.User,
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
) http.Handler {
	t.Helper()
	localProvider := tslocalid.MustTestIdentity(t, testPublicOrigin, "").ProviderDomain
	h := inboxinvites.NewHandler(
		repo,
		httpClient,
		discoveryClient,
		signer,
		localProvider,
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
			_ = json.NewEncoder(w).Encode(spec.Discovery{
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
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, inviteAcceptedCalls, sawSignature
}

func createInviteForUser(repo *invitesinbox.MemoryIncomingInviteRepo, recipientUserID, token, senderFQDN string) *invitesinbox.IncomingInvite {
	invite := &invitesinbox.IncomingInvite{
		Token:           token,
		SenderFQDN:      senderFQDN,
		RecipientUserID: recipientUserID,
		Status:          invites.InviteStatusPending,
	}
	repo.Create(context.Background(), invite)
	return invite
}

func buildInviteString(token, providerFQDN string) string {
	inner := token + "@" + providerFQDN
	return base64.StdEncoding.EncodeToString([]byte(inner))
}
