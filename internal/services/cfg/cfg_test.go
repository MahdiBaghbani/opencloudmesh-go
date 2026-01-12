package cfg

import (
	"testing"
)

// testConfig is a config struct for testing.
type testConfig struct {
	Name    string `mapstructure:"name"`
	Count   int    `mapstructure:"count"`
	Enabled bool   `mapstructure:"enabled"`
}

// testConfigWithDefaults implements Setter.
type testConfigWithDefaults struct {
	Name    string `mapstructure:"name"`
	Count   int    `mapstructure:"count"`
	Enabled bool   `mapstructure:"enabled"`
}

func (c *testConfigWithDefaults) ApplyDefaults() {
	if c.Name == "" {
		c.Name = "default-name"
	}
	if c.Count == 0 {
		c.Count = 42
	}
}

func TestDecode_Basic(t *testing.T) {
	input := map[string]any{
		"name":    "test",
		"count":   10,
		"enabled": true,
	}

	var c testConfig
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Name != "test" {
		t.Errorf("Expected name 'test', got %q", c.Name)
	}
	if c.Count != 10 {
		t.Errorf("Expected count 10, got %d", c.Count)
	}
	if !c.Enabled {
		t.Error("Expected enabled true, got false")
	}
}

func TestDecode_PartialInput(t *testing.T) {
	input := map[string]any{
		"name": "partial",
	}

	var c testConfig
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Name != "partial" {
		t.Errorf("Expected name 'partial', got %q", c.Name)
	}
	if c.Count != 0 {
		t.Errorf("Expected count 0 (zero value), got %d", c.Count)
	}
	if c.Enabled {
		t.Error("Expected enabled false (zero value), got true")
	}
}

func TestDecode_CallsApplyDefaults(t *testing.T) {
	input := map[string]any{
		"enabled": true,
	}

	var c testConfigWithDefaults
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// ApplyDefaults should have been called
	if c.Name != "default-name" {
		t.Errorf("Expected name 'default-name' from ApplyDefaults, got %q", c.Name)
	}
	if c.Count != 42 {
		t.Errorf("Expected count 42 from ApplyDefaults, got %d", c.Count)
	}
	if !c.Enabled {
		t.Error("Expected enabled true from input, got false")
	}
}

func TestDecode_ApplyDefaultsDoesNotOverwrite(t *testing.T) {
	input := map[string]any{
		"name":  "explicit",
		"count": 99,
	}

	var c testConfigWithDefaults
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// ApplyDefaults should not overwrite explicit values
	if c.Name != "explicit" {
		t.Errorf("Expected name 'explicit', got %q", c.Name)
	}
	if c.Count != 99 {
		t.Errorf("Expected count 99, got %d", c.Count)
	}
}

func TestDecode_EmptyInput(t *testing.T) {
	input := map[string]any{}

	var c testConfigWithDefaults
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// All defaults should be applied
	if c.Name != "default-name" {
		t.Errorf("Expected name 'default-name', got %q", c.Name)
	}
	if c.Count != 42 {
		t.Errorf("Expected count 42, got %d", c.Count)
	}
}

func TestDecode_NilInput(t *testing.T) {
	var c testConfigWithDefaults
	err := Decode(nil, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Defaults should still be applied
	if c.Name != "default-name" {
		t.Errorf("Expected name 'default-name', got %q", c.Name)
	}
}

// nestedConfig tests nested struct decoding.
type nestedConfig struct {
	Outer string       `mapstructure:"outer"`
	Inner *innerConfig `mapstructure:"inner"`
}

type innerConfig struct {
	Value string `mapstructure:"value"`
}

func TestDecode_NestedStruct(t *testing.T) {
	input := map[string]any{
		"outer": "outer-value",
		"inner": map[string]any{
			"value": "inner-value",
		},
	}

	var c nestedConfig
	err := Decode(input, &c)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Outer != "outer-value" {
		t.Errorf("Expected outer 'outer-value', got %q", c.Outer)
	}
	if c.Inner == nil {
		t.Fatal("Expected inner to be non-nil")
	}
	if c.Inner.Value != "inner-value" {
		t.Errorf("Expected inner.value 'inner-value', got %q", c.Inner.Value)
	}
}
