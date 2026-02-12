// Package cfg provides config decoding for services (mapstructure, Setter for defaults).
package cfg

import (
	"fmt"
	"sort"

	"github.com/mitchellh/mapstructure"
)

// Setter is the interface for applying default options after decode.
type Setter interface {
	ApplyDefaults()
}

// Decode decodes input map to c; calls ApplyDefaults if c implements Setter.
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

	// Call ApplyDefaults if implemented
	if s, ok := c.(Setter); ok {
		s.ApplyDefaults()
	}

	return nil
}

// DecodeWithUnused decodes input to c and returns unused keys (sorted).
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

// MustDecodeStrict decodes input to c; returns error if any keys are unused.
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
