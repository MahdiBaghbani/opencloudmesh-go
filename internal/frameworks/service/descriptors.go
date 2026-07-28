package service

// BuildKey identifies the wiring builder for a core service. Keys live in the
// service package so descriptors stay cycle-free; wiring maps keys to builders.
type BuildKey string

const (
	// BuildWellknown is the well-known service build key.
	BuildWellknown BuildKey = "wellknown"
	// BuildOCM is the OCM service build key.
	BuildOCM BuildKey = "ocm"
	// BuildOCMAux is the OCM auxiliary service build key.
	BuildOCMAux BuildKey = "ocmaux"
	// BuildAPI is the API service build key.
	BuildAPI BuildKey = "api"
	// BuildUI is the UI service build key.
	BuildUI BuildKey = "ui"
	// BuildWebDAV is the WebDAV service build key.
	BuildWebDAV BuildKey = "webdav"
)

// Descriptor is the canonical registration entry for one core HTTP service.
// Name is the config/wiring key; Prefix is the chi mount segment (ocmaux uses
// "ocm-aux" while Name stays "ocmaux"). Build selects the wiring builder.
type Descriptor struct {
	Name        string
	MountAtRoot bool
	Prefix      string
	Build       BuildKey
}

var descriptors = []Descriptor{
	{
		Name:        "wellknown",
		MountAtRoot: true,
		Prefix:      "",
		Build:       BuildWellknown,
	},
	{
		Name:        "ocm",
		MountAtRoot: false,
		Prefix:      "ocm",
		Build:       BuildOCM,
	},
	{
		Name:        "ocmaux",
		MountAtRoot: false,
		Prefix:      "ocm-aux",
		Build:       BuildOCMAux,
	},
	{
		Name:        "api",
		MountAtRoot: false,
		Prefix:      "api",
		Build:       BuildAPI,
	},
	{
		Name:        "ui",
		MountAtRoot: false,
		Prefix:      "ui",
		Build:       BuildUI,
	},
	{
		Name:        "webdav",
		MountAtRoot: false,
		Prefix:      "webdav",
		Build:       BuildWebDAV,
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
