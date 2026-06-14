package service

import (
	"strings"
)

// RegisteredRouteSpecs collects service-owned route specs in descriptor order.
func RegisteredRouteSpecs(opts RouteOpts) []RouteSpec {
	out := make([]RouteSpec, 0, 64)
	for _, registrar := range routeSpecRegistrars {
		specs := registrar(opts)
		for _, spec := range specs {
			if featureActive(spec.FeatureCondition, opts) {
				out = append(out, spec)
			}
		}
	}
	return out
}

// Routes is the sole canonical route-policy aggregate.
func Routes(opts RouteOpts) []RouteRow {
	specs := RegisteredRouteSpecs(opts)
	rows := make([]RouteRow, 0, len(specs)+len(descriptors))
	for _, spec := range specs {
		desc, ok := DescriptorByName(spec.Service)
		if !ok {
			continue
		}
		rows = append(rows, RouteRow{
			RouteSpec:     spec,
			MountAtRoot:   desc.MountAtRoot,
			ServicePrefix: desc.Prefix,
			FullPath:      fullPathForSpec(desc, opts.ExternalBasePath, spec.Pattern),
			AtHostRoot:    desc.MountAtRoot,
		})
	}
	rows = append(rows, syntheticSubtreeRows(opts)...)
	return rows
}

func fullPathForSpec(desc Descriptor, basePath, pattern string) string {
	if desc.MountAtRoot {
		return pattern
	}
	var segments []string
	if basePath != "" {
		segments = append(segments, strings.Trim(basePath, "/"))
	}
	if desc.Prefix != "" {
		segments = append(segments, desc.Prefix)
	}
	if pattern != "" {
		segments = append(segments, strings.TrimPrefix(pattern, "/"))
	}
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

func syntheticSubtreeRows(opts RouteOpts) []RouteRow {
	rows := make([]RouteRow, 0, 2)
	for _, desc := range descriptors {
		if desc.MountAtRoot {
			continue
		}
		prefix := subtreePrefix(desc, opts.ExternalBasePath)
		if prefix == "" {
			continue
		}
		policy := defaultSubtreeSessionPolicy(desc.Name)
		rows = append(rows, RouteRow{
			RouteSpec: RouteSpec{
				ID:            SubtreeDefaultID(desc.Name),
				Service:       desc.Name,
				SessionPolicy: policy,
				SurfaceClass:  surfaceClassForService(desc.Name),
			},
			MountAtRoot:   false,
			ServicePrefix: desc.Prefix,
			FullPath:      prefix,
			AtHostRoot:    false,
			Synthetic:     true,
		})
	}
	return rows
}

func subtreePrefix(desc Descriptor, basePath string) string {
	if desc.Prefix == "" {
		return ""
	}
	if basePath == "" {
		return "/" + desc.Prefix
	}
	return strings.TrimSuffix(basePath, "/") + "/" + desc.Prefix
}

func defaultSubtreeSessionPolicy(serviceName string) SessionPolicy {
	switch serviceName {
	case "api", "ui":
		return SessionProtected
	default:
		return SessionPublic
	}
}

func surfaceClassForService(serviceName string) SurfaceClass {
	switch serviceName {
	case "wellknown":
		return SurfaceDiscovery
	case "ocm":
		return SurfaceProtocol
	case "ocmaux":
		return SurfaceHelper
	case "api":
		return SurfaceAPI
	case "ui":
		return SurfaceUI
	case "webdav":
		return SurfaceWebDAV
	default:
		return ""
	}
}
