package service

// RouteSpecRegistrar returns service-owned route specs for the given opts.
type RouteSpecRegistrar func(opts RouteOpts) []RouteSpec

var routeSpecRegistrars []RouteSpecRegistrar

// RegisterRouteSpecs registers a service-owned route spec provider. Services
// call this from init() to avoid import cycles with the framework package.
func RegisterRouteSpecs(registrar RouteSpecRegistrar) {
	routeSpecRegistrars = append(routeSpecRegistrars, registrar)
}
