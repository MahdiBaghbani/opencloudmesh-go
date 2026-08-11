// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

type notifyHarness struct {
	targetHost          string
	gotNotificationURL  string
	gotNotificationBody string
	notifyStatus        int
}

func newNotifyHarness(t *testing.T, capabilities []string, notifyStatus int) (*outgoing.Sender, *notifyHarness) {
	t.Helper()

	h := &notifyHarness{notifyStatus: notifyStatus}

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:      true,
				APIVersion:   spec.APIVersionPin,
				EndPoint:     srv.URL + "/ocm",
				Capabilities: capabilities,
			})
		case "/ocm/notifications":
			h.gotNotificationURL = r.URL.String()

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read notification body: %v", err)
			}

			h.gotNotificationBody = string(body)
			w.WriteHeader(h.notifyStatus)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	h.targetHost = parsed.Host

	rawClient := httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: 1 << 20,
	}, nil)
	discClient := discovery.NewClient(rawClient, nil)

	km := crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	poster := outbound.NewPoster(
		httpclient.NewContextClient(rawClient),
		discClient,
		crypto.NewRFC9421Signer(km),
		peerorigin.NewResolver(true),
	)

	return outgoing.NewSender(poster), h
}

func TestSender_Notify_Success(t *testing.T) {
	t.Parallel()

	sender, harness := newNotifyHarness(t, []string{spec.CapabilityNotifications}, http.StatusOK)

	err := sender.Notify(
		context.Background(),
		harness.targetHost,
		"provider-1",
		"file",
		spec.NotificationTypeShareAccepted,
		nil,
	)
	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	if !strings.HasSuffix(harness.gotNotificationURL, "/ocm/notifications") {
		t.Fatalf("url = %q, want notifications endpoint", harness.gotNotificationURL)
	}

	if !strings.Contains(harness.gotNotificationBody, `"notificationType":"SHARE_ACCEPTED"`) {
		t.Fatalf("body = %q, want share accepted notification", harness.gotNotificationBody)
	}

	if !strings.Contains(harness.gotNotificationBody, `"providerId":"provider-1"`) {
		t.Fatalf("body = %q, want providerId", harness.gotNotificationBody)
	}
}

func TestSender_Notify_NotAdvertised(t *testing.T) {
	t.Parallel()

	sender, harness := newNotifyHarness(t, nil, http.StatusOK)

	err := sender.Notify(
		context.Background(),
		harness.targetHost,
		"provider-1",
		"file",
		spec.NotificationTypeShareDeclined,
		nil,
	)
	if !errors.Is(err, notifications.ErrNotificationsNotAdvertised) {
		t.Fatalf("expected ErrNotificationsNotAdvertised, got %v", err)
	}

	if harness.gotNotificationURL != "" {
		t.Fatalf("expected no notification POST when capability missing, got %q", harness.gotNotificationURL)
	}
}

func TestSender_Notify_Non2xx(t *testing.T) {
	t.Parallel()

	sender, harness := newNotifyHarness(t, []string{spec.CapabilityNotifications}, http.StatusBadRequest)

	err := sender.Notify(
		context.Background(),
		harness.targetHost,
		"provider-1",
		"file",
		spec.NotificationTypeShareAccepted,
		nil,
	)
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}

	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("error = %v, want status 400", err)
	}

	if harness.gotNotificationBody == "" {
		t.Fatal("expected notification POST body")
	}
}

func TestSender_Notify_2xxCreated(t *testing.T) {
	t.Parallel()

	sender, harness := newNotifyHarness(t, []string{spec.CapabilityNotifications}, http.StatusCreated)

	err := sender.Notify(
		context.Background(),
		harness.targetHost,
		"provider-1",
		"file",
		spec.NotificationTypeShareAccepted,
		nil,
	)
	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	if harness.gotNotificationURL == "" {
		t.Fatal("expected notification POST")
	}
}
