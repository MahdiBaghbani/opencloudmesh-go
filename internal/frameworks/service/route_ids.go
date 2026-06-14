package service

const (
	RouteIDOCMToken          = "ocm-token"
	RouteIDWebDAVOCMWildcard = "webdav-ocm-wildcard"
	RouteIDUIAcceptInvite    = "ui-accept-invite"
	RouteIDUIWAYF            = "ui-wayf"
	RouteIDAPIHealthz        = "api-healthz"
)

const subtreeDefaultIDSuffix = "-subtree-default"

// SubtreeDefaultID returns the synthetic subtree route ID for a service name.
func SubtreeDefaultID(serviceName string) string {
	return serviceName + subtreeDefaultIDSuffix
}
