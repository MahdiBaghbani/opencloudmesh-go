package inbox

import "context"

// NotificationSender sends acceptance/decline notifications to remote servers.
type NotificationSender interface {
	SendShareAccepted(ctx context.Context, targetHost, providerID, resourceType string) error
	SendShareDeclined(ctx context.Context, targetHost, providerID, resourceType string) error
}
