// Package cfg provides config decoding utilities for services.
// Matches Reva's pkg/utils/cfg/cfg.go with Setter interface.
package cfg

import (
	"fmt"
	"sort"

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

// DecodeWithUnused decodes input to c and returns any unused keys (sorted).
// If c implements Setter, ApplyDefaults() is called automatically.
// Use this when you want to warn about unused config keys at the call site.
func DecodeWithUnused(input map[string]any, c any) ([]string, error) {
	var md mapstructure.Metadata
	config := &mapstructure.DecoderConfig{
		Metadata: &md,
		Result:   c,
		TagName:  "mapstructure",
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(input); err != nil {
		return nil, err
	}

	if s, ok := c.(Setter); ok {
		s.ApplyDefaults()
	}

	// Sort unused keys for deterministic output
	unused := md.Unused
	sort.Strings(unused)

	return unused, nil
}

// MustDecodeStrict decodes input to c and returns an error if any keys are unused.
// Use this in tests to catch dead config.
func MustDecodeStrict(input map[string]any, c any) error {
	unused, err := DecodeWithUnused(input, c)
	if err != nil {
		return err
	}
	if len(unused) > 0 {
		return fmt.Errorf("unused config keys: %v", unused)
	}
	return nil
}
