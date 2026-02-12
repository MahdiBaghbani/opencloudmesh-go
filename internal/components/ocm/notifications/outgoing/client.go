package outgoing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

type Client struct {
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *outboundsigning.OutboundPolicy
}

func NewClient(
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
	outboundPolicy *outboundsigning.OutboundPolicy,
) *Client {
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
	}
}

func (c *Client) SendNotification(ctx context.Context, targetHost string, notification *notifications.NewNotification) error {
	if c.discoveryClient == nil {
		return fmt.Errorf("discovery client not configured, cannot send notification to %s", targetHost)
	}
	baseURL := "https://" + targetHost
	disc, err := c.discoveryClient.Discover(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("discovery failed for %s: %w", targetHost, err)
	}
	notificationsURL, err := url.JoinPath(disc.EndPoint, "notifications")
	if err != nil {
		return fmt.Errorf("failed to build notifications URL: %w", err)
	}
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to encode notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notificationsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.outboundPolicy != nil {
		decision := c.outboundPolicy.ShouldSign(
			outboundsigning.EndpointNotifications,
			targetHost,
			disc,
			c.signer != nil,
		)
		if decision.Error != nil {
			return fmt.Errorf("outbound signing policy error: %w", decision.Error)
		}
		if decision.ShouldSign && c.signer != nil {
			if err := c.signer.SignRequest(req, body); err != nil {
				return fmt.Errorf("failed to sign request: %w", err)
			}
		}
	} else if c.signer != nil && disc.HasCapability("http-sig") && len(disc.PublicKeys) > 0 {
		if err := c.signer.SignRequest(req, body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}
	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification rejected with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (c *Client) SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error {
	return c.SendNotification(ctx, targetHost, &notifications.NewNotification{
		NotificationType: notifications.NotificationShareAccepted,
		ResourceType:     resourceType,
		ProviderID:       providerID,
	})
}

func (c *Client) SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error {
	return c.SendNotification(ctx, targetHost, &notifications.NewNotification{
		NotificationType: notifications.NotificationShareDeclined,
		ResourceType:     resourceType,
		ProviderID:       providerID,
	})
}
