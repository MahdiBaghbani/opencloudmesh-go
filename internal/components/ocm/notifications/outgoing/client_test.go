// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	notificationsoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func newNotificationClients(t *testing.T) (*httpclient.ContextClient, *discovery.Client) {
	t.Helper()
	outboundCfg := &config.OutboundHTTPConfig{
		SSRFMode:           "off",
		InsecureSkipVerify: true,
		MaxResponseBytes:   1 << 20,
	}
	requestClient := httpclient.NewContextClient(httpclient.New(outboundCfg, nil))
	discoveryClient := discovery.NewClient(httpclient.New(outboundCfg, nil), nil)
	return requestClient, discoveryClient
}

func startNotificationReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	notificationCalls := &atomic.Int32{}
	sawSignature := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery.Discovery{
				Enabled:      true,
				APIVersion:   "1.2.2",
				EndPoint:     srv.URL + "/ocm",
				Capabilities: []string{"exchange-token"},
			})
		case "/ocm/notifications":
			notificationCalls.Add(1)
			if r.Header.Get("Signature") != "" {
				sawSignature.Store(1)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, notificationCalls, sawSignature
}

func TestClient_SendNotification_StrictWithoutSignerReturnsPolicyError(t *testing.T) {
	receiver, notificationCalls, _ := startNotificationReceiver(t)
	defer receiver.Close()

	requestClient, discoveryClient := newNotificationClients(t)
	client := notificationsoutgoing.NewClient(
		requestClient,
		discoveryClient,
		nil,
		&outboundsigning.OutboundPolicy{OutboundMode: "strict"},
	)
	targetHost := strings.TrimPrefix(receiver.URL, "https://")

	err := client.SendNotification(context.Background(), targetHost, &notifications.NewNotification{
		NotificationType: notifications.NotificationShareAccepted,
		ResourceType:     "file",
		ProviderID:       "provider-a",
	})
	if err == nil {
		t.Fatal("expected outbound signing policy error for strict mode without signer")
	}
	if !strings.Contains(err.Error(), "outbound signing policy error") {
		t.Fatalf("expected policy error, got %v", err)
	}
	if notificationCalls.Load() != 0 {
		t.Fatalf("expected notification endpoint not called, got %d calls", notificationCalls.Load())
	}
}

func TestClient_SendNotification_TokenOnlyModeSkipsSigning(t *testing.T) {
	receiver, notificationCalls, sawSignature := startNotificationReceiver(t)
	defer receiver.Close()

	requestClient, discoveryClient := newNotificationClients(t)
	client := notificationsoutgoing.NewClient(
		requestClient,
		discoveryClient,
		nil,
		&outboundsigning.OutboundPolicy{OutboundMode: "token-only"},
	)
	targetHost := strings.TrimPrefix(receiver.URL, "https://")

	err := client.SendNotification(context.Background(), targetHost, &notifications.NewNotification{
		NotificationType: notifications.NotificationShareAccepted,
		ResourceType:     "file",
		ProviderID:       "provider-a",
	})
	if err != nil {
		t.Fatalf("expected token-only mode to allow unsigned notification request, got %v", err)
	}
	if notificationCalls.Load() != 1 {
		t.Fatalf("expected one notification request, got %d", notificationCalls.Load())
	}
	if sawSignature.Load() != 0 {
		t.Fatal("did not expect Signature header in token-only notifications path")
	}
}
