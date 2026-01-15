package cfg

import (
	"testing"
)

type testConfig struct {
	Name    string `mapstructure:"name"`
	Port    int    `mapstructure:"port"`
	Enabled bool   `mapstructure:"enabled"`
}

func (c *testConfig) ApplyDefaults() {
	if c.Port == 0 {
		c.Port = 8080
	}
}

func TestDecode_Basic(t *testing.T) {
	input := map[string]any{
		"name":    "test-service",
		"port":    9000,
		"enabled": true,
	}

	var c testConfig
	if err := Decode(input, &c); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Name != "test-service" {
		t.Errorf("Name = %q, want %q", c.Name, "test-service")
	}
	if c.Port != 9000 {
		t.Errorf("Port = %d, want %d", c.Port, 9000)
	}
	if !c.Enabled {
		t.Error("Enabled = false, want true")
	}
}

func TestDecode_ApplyDefaults(t *testing.T) {
	input := map[string]any{
		"name": "test-service",
	}

	var c testConfig
	if err := Decode(input, &c); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if c.Port != 8080 {
		t.Errorf("Port = %d, want default %d", c.Port, 8080)
	}
}

func TestDecodeWithUnused_ReportsUnusedKeys(t *testing.T) {
	input := map[string]any{
		"name":        "test-service",
		"port":        9000,
		"unknown_key": "value",
		"another_bad": 123,
	}

	var c testConfig
	unused, err := DecodeWithUnused(input, &c)
	if err != nil {
		t.Fatalf("DecodeWithUnused failed: %v", err)
	}

	if len(unused) != 2 {
		t.Fatalf("len(unused) = %d, want 2", len(unused))
	}

	// Keys should be sorted
	if unused[0] != "another_bad" {
		t.Errorf("unused[0] = %q, want %q", unused[0], "another_bad")
	}
	if unused[1] != "unknown_key" {
		t.Errorf("unused[1] = %q, want %q", unused[1], "unknown_key")
	}

	// Config should still be decoded correctly
	if c.Name != "test-service" {
		t.Errorf("Name = %q, want %q", c.Name, "test-service")
	}
}

func TestDecodeWithUnused_NoUnusedKeys(t *testing.T) {
	input := map[string]any{
		"name": "test-service",
		"port": 9000,
	}

	var c testConfig
	unused, err := DecodeWithUnused(input, &c)
	if err != nil {
		t.Fatalf("DecodeWithUnused failed: %v", err)
	}

	if len(unused) != 0 {
		t.Errorf("len(unused) = %d, want 0", len(unused))
	}
}

func TestDecodeWithUnused_ApplyDefaults(t *testing.T) {
	input := map[string]any{
		"name": "test-service",
	}

	var c testConfig
	_, err := DecodeWithUnused(input, &c)
	if err != nil {
		t.Fatalf("DecodeWithUnused failed: %v", err)
	}

	if c.Port != 8080 {
		t.Errorf("Port = %d, want default %d", c.Port, 8080)
	}
}

func TestMustDecodeStrict_FailsOnUnusedKeys(t *testing.T) {
	input := map[string]any{
		"name":        "test-service",
		"unknown_key": "value",
	}

	var c testConfig
	err := MustDecodeStrict(input, &c)
	if err == nil {
		t.Fatal("MustDecodeStrict should have failed on unused keys")
	}

	// Error message should contain the unused key
	if err.Error() != "unused config keys: [unknown_key]" {
		t.Errorf("error = %q, want message containing unused key", err.Error())
	}
}

func TestMustDecodeStrict_PassesWithNoUnusedKeys(t *testing.T) {
	input := map[string]any{
		"name":    "test-service",
		"port":    9000,
		"enabled": true,
	}

	var c testConfig
	err := MustDecodeStrict(input, &c)
	if err != nil {
		t.Fatalf("MustDecodeStrict should have passed: %v", err)
	}

	if c.Name != "test-service" {
		t.Errorf("Name = %q, want %q", c.Name, "test-service")
	}
}

func TestMustDecodeStrict_ApplyDefaults(t *testing.T) {
	input := map[string]any{
		"name": "test-service",
	}

	var c testConfig
	err := MustDecodeStrict(input, &c)
	if err != nil {
		t.Fatalf("MustDecodeStrict failed: %v", err)
	}

	if c.Port != 8080 {
		t.Errorf("Port = %d, want default %d", c.Port, 8080)
	}
}
