package outgoing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

type Client struct {
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *outboundsigning.OutboundPolicy
	peerContract    *peercompat.CompiledContract
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

// SetPeerContract wires the compiled compatibility contract so discovery and
// signing decisions use one shared peer-origin resolver.
func (c *Client) SetPeerContract(peerContract *peercompat.CompiledContract) {
	c.peerContract = peerContract
}

func (c *Client) SendNotification(ctx context.Context, targetHost string, notification *notifications.NewNotification) error {
	if c.discoveryClient == nil {
		return fmt.Errorf("discovery client not configured, cannot send notification to %s", targetHost)
	}
	if c.outboundPolicy == nil {
		return fmt.Errorf("outbound signing policy not configured for notifications")
	}
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to encode notification: %w", err)
	}
	poster := outbound.NewPoster(c.httpClient, c.discoveryClient, c.signer, c.outboundPolicy, c.peerContract)
	resp, err := poster.Send(ctx, outbound.Request{
		TargetHost:   targetHost,
		EndpointPath: "notifications",
		Kind:         outboundsigning.EndpointNotifications,
		Body:         body,
	})
	if err != nil {
		return err
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
