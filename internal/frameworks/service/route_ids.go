package service

const (
	// RouteIDOCMToken is the OCM token route identifier.
	RouteIDOCMToken = "ocm-token"
	// RouteIDWebDAVOCMWildcard is the WebDAV OCM wildcard route identifier.
	RouteIDWebDAVOCMWildcard = "webdav-ocm-wildcard"
	// RouteIDUIAcceptInvite is the UI accept-invite route identifier.
	RouteIDUIAcceptInvite = "ui-accept-invite"
	// RouteIDUIWAYF is the UI WAYF route identifier.
	RouteIDUIWAYF = "ui-wayf"
	// RouteIDAPIHealthz is the API health check route identifier.
	RouteIDAPIHealthz = "api-healthz"
)

const subtreeDefaultIDSuffix = "-subtree-default"

// SubtreeDefaultID returns the synthetic subtree route ID for a service name.
func SubtreeDefaultID(serviceName string) string {
	return serviceName + subtreeDefaultIDSuffix
}
