package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
)

// HTTPClient interface for outbound requests.
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Client sends notifications to remote OCM servers.
type Client struct {
	httpClient      HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *federation.OutboundPolicy
}

// NewClient creates a new notifications client.
func NewClient(
	httpClient HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
	outboundPolicy *federation.OutboundPolicy,
) *Client {
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
	}
}

// SendNotification sends a notification to a remote server.
func (c *Client) SendNotification(ctx context.Context, targetHost string, notification *NewNotification) error {
	// Check if discovery client is available
	if c.discoveryClient == nil {
		return fmt.Errorf("discovery client not configured, cannot send notification to %s", targetHost)
	}

	// Discover the target's endpoint
	baseURL := "https://" + targetHost
	disc, err := c.discoveryClient.Discover(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("discovery failed for %s: %w", targetHost, err)
	}

	// Build notifications URL
	notificationsURL, err := url.JoinPath(disc.EndPoint, "notifications")
	if err != nil {
		return fmt.Errorf("failed to build notifications URL: %w", err)
	}

	// Encode payload
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to encode notification: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, notificationsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply outbound signing policy
	if c.outboundPolicy != nil {
		decision := c.outboundPolicy.ShouldSign(
			federation.EndpointNotifications,
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
		// Fallback for backward compatibility when no policy is set
		if err := c.signer.SignRequest(req, body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}

	// Send request
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

// SendShareAccepted sends a SHARE_ACCEPTED notification.
func (c *Client) SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error {
	return c.SendNotification(ctx, targetHost, &NewNotification{
		NotificationType: NotificationShareAccepted,
		ResourceType:     resourceType,
		ProviderID:       providerID,
	})
}

// SendShareDeclined sends a SHARE_DECLINED notification.
func (c *Client) SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error {
	return c.SendNotification(ctx, targetHost, &NewNotification{
		NotificationType: NotificationShareDeclined,
		ResourceType:     resourceType,
		ProviderID:       providerID,
	})
}
