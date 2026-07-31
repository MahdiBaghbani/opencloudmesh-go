// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"sort"
)

var (
	// CoreServices lists service names always constructed via the descriptor table.
	CoreServices = coreServiceNames()
	// RootService is the core service mounted at the host root rather than under
	// external_base_path.
	RootService = rootServiceName()
)

func coreServiceNames() []string {
	names := make([]string, len(descriptors))
	for i, d := range descriptors {
		names[i] = d.Name
	}

	return names
}

func rootServiceName() string {
	for _, d := range descriptors {
		if d.MountAtRoot {
			return d.Name
		}
	}

	return ""
}

// AppServices returns the core service names mounted under external_base_path,
// in CoreServices order, excluding RootService (mounted at the host root).
// Order is significant for Chi route matching, so it mirrors CoreServices.
func AppServices() []string {
	names := make([]string, 0, len(descriptors))
	for _, d := range descriptors {
		if d.MountAtRoot {
			continue
		}

		names = append(names, d.Name)
	}

	return names
}

// CheckServiceNames validates names against service.CoreServices.
// When any name is not a core service, it returns unknown sorted and allowed in CoreServices mount order;
// when all names are valid, it returns nil, nil. Callers own nil-map guarding.
func CheckServiceNames(names []string) (unknown, allowed []string) {
	allowedSet := make(map[string]struct{}, len(CoreServices))
	for _, n := range CoreServices {
		allowedSet[n] = struct{}{}
	}

	for _, name := range names {
		if _, ok := allowedSet[name]; !ok {
			unknown = append(unknown, name)
		}
	}

	if len(unknown) == 0 {
		return nil, nil
	}

	sort.Strings(unknown)

	allowed = append([]string(nil), CoreServices...)

	return unknown, allowed
}
