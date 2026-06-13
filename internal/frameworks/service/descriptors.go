package service

// RouteGroupSpec defines auth and path metadata for one mounted route group.
type RouteGroupSpec struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool
}

// BuildKey identifies the wiring builder for a core service. Keys live in the
// service package so descriptors stay cycle-free; wiring maps keys to builders.
type BuildKey string

const (
	BuildWellknown BuildKey = "wellknown"
	BuildOCM       BuildKey = "ocm"
	BuildOCMAux    BuildKey = "ocmaux"
	BuildAPI       BuildKey = "api"
	BuildUI        BuildKey = "ui"
	BuildWebDAV    BuildKey = "webdav"
)

// Descriptor is the canonical registration entry for one core HTTP service.
// Name is the config/wiring key; Prefix is the chi mount segment (ocmaux uses
// "ocm-aux" while Name stays "ocmaux"). Build selects the wiring builder.
type Descriptor struct {
	Name        string
	MountAtRoot bool
	Prefix      string
	Build       BuildKey
	RouteGroups []RouteGroupSpec
}

var descriptors = []Descriptor{
	{
		Name:        "wellknown",
		MountAtRoot: true,
		Prefix:      "",
		Build:       BuildWellknown,
		RouteGroups: []RouteGroupSpec{
			{Name: "well-known-ocm", PathPrefix: "/.well-known/ocm", RequiresAuth: false, AtHostRoot: true},
			{Name: "ocm-provider", PathPrefix: "/ocm-provider", RequiresAuth: false, AtHostRoot: true},
		},
	},
	{
		Name:        "ocm",
		MountAtRoot: false,
		Prefix:      "ocm",
		Build:       BuildOCM,
		RouteGroups: []RouteGroupSpec{
			{Name: "ocm-api", PathPrefix: "/ocm", RequiresAuth: false, AtHostRoot: false},
		},
	},
	{
		Name:        "ocmaux",
		MountAtRoot: false,
		Prefix:      "ocm-aux",
		Build:       BuildOCMAux,
		RouteGroups: []RouteGroupSpec{
			{Name: "ocm-aux", PathPrefix: "/ocm-aux", RequiresAuth: false, AtHostRoot: false},
		},
	},
	{
		Name:        "api",
		MountAtRoot: false,
		Prefix:      "api",
		Build:       BuildAPI,
		RouteGroups: []RouteGroupSpec{
			{Name: "api", PathPrefix: "/api", RequiresAuth: true, AtHostRoot: false},
		},
	},
	{
		Name:        "ui",
		MountAtRoot: false,
		Prefix:      "ui",
		Build:       BuildUI,
		RouteGroups: []RouteGroupSpec{
			{Name: "ui", PathPrefix: "/ui", RequiresAuth: true, AtHostRoot: false},
		},
	},
	{
		Name:        "webdav",
		MountAtRoot: false,
		Prefix:      "webdav",
		Build:       BuildWebDAV,
		RouteGroups: []RouteGroupSpec{
			{Name: "webdav", PathPrefix: "/webdav/ocm", RequiresAuth: false, AtHostRoot: false},
		},
	},
}

// Descriptors returns the canonical core service descriptor table in mount order.
func Descriptors() []Descriptor {
	return append([]Descriptor(nil), descriptors...)
}

// DescriptorByName returns a descriptor by service name.
func DescriptorByName(name string) (Descriptor, bool) {
	for _, d := range descriptors {
		if d.Name == name {
			return d, true
		}
	}
	return Descriptor{}, false
}

// RouteGroupsFromDescriptors flattens descriptor route groups in service order.
func RouteGroupsFromDescriptors() []RouteGroupSpec {
	out := make([]RouteGroupSpec, 0, len(descriptors)+1)
	for _, d := range descriptors {
		out = append(out, d.RouteGroups...)
	}
	return out
}
