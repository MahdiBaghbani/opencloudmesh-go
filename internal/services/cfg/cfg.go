// Package cfg provides config decoding utilities for services.
// Matches Reva's pkg/utils/cfg/cfg.go with Setter interface.
package cfg

import (
	"github.com/mitchellh/mapstructure"
)

// Setter is the interface a configuration struct may implement
// to set default options. Matches Reva's pkg/utils/cfg.Setter.
type Setter interface {
	ApplyDefaults()
}

// Decode decodes the given raw input map to the target pointer c.
// If c implements Setter, ApplyDefaults() is called automatically.
func Decode(input map[string]any, c any) error {
	config := &mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   c,
		TagName:  "mapstructure",
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}
	if err := decoder.Decode(input); err != nil {
		return err
	}

	// Call ApplyDefaults if implemented (Reva pattern)
	if s, ok := c.(Setter); ok {
		s.ApplyDefaults()
	}

	return nil
}
