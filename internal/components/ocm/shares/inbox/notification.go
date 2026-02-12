package inbox

import "context"

type NotificationSender interface {
	SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error
	SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error
}
