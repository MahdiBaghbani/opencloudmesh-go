// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
			MatchExact:    validatorMatchExact(spec.ID),
		})
	}

	rows = append(rows, syntheticSubtreeRows(opts)...)

	return rows
}

func validatorMatchExact(id string) bool {
	if id == "" || !strings.HasPrefix(id, string(BuildValidator)+"-") {
		return false
	}

	return !strings.HasSuffix(id, subtreeDefaultIDSuffix)
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
	case string(BuildValidator):
		return SessionProtected
	case string(BuildAPI), string(BuildUI):
		return SessionProtected
	default:
		return SessionPublic
	}
}

func surfaceClassForService(serviceName string) SurfaceClass {
	switch serviceName {
	case string(BuildWellknown):
		return SurfaceDiscovery
	case string(BuildOCM):
		return SurfaceProtocol
	case string(BuildOCMAux):
		return SurfaceHelper
	case string(BuildAPI):
		return SurfaceAPI
	case string(BuildUI):
		return SurfaceUI
	case string(BuildWebDAV):
		return SurfaceWebDAV
	case string(BuildValidator):
		return SurfaceAPI
	default:
		return ""
	}
}
