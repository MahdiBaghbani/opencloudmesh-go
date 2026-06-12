package service

import (
	"sort"
)

// CoreServices lists service names always constructed via the static wiring table.
var CoreServices = []string{"wellknown", "ocm", "ocmaux", "api", "ui", "webdav"}

// RootService is the core service mounted at the host root rather than under
// external_base_path. Every other CoreServices entry is mounted as an app
// endpoint. This marker keeps route mounting derived from CoreServices instead
// of a separate hardcoded list.
const RootService = "wellknown"

// AppServices returns the core service names mounted under external_base_path,
// in CoreServices order, excluding RootService (mounted at the host root).
// Order is significant for Chi route matching, so it mirrors CoreServices.
func AppServices() []string {
	names := make([]string, 0, len(CoreServices))
	for _, name := range CoreServices {
		if name == RootService {
			continue
		}
		names = append(names, name)
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
