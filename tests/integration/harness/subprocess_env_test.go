// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package harness

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// envMap converts a "KEY=VALUE" slice into a map keyed by env var name.
func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			// Bare "KEY" form with no value.
			m[key] = ""
			continue
		}
		m[key] = value
	}
	return m
}

// TestScrubSubprocessEnvRemovesBlocklistedVars asserts scrubSubprocessEnv drops
// every OCM_CONFIG_* variable the harness blocklists, in both "KEY=VALUE" and
// bare "KEY" forms, while preserving unrelated environment variables.
func TestScrubSubprocessEnvRemovesBlocklistedVars(t *testing.T) {
	// Build an input env that includes every blocklisted var plus unrelated
	// vars the binary still needs. Include both "KEY=VALUE" and bare "KEY"
	// forms so the helper's handling of both is exercised.
	input := make([]string, 0, len(hermeticEnvBlocklist)+4)
	for _, k := range hermeticEnvBlocklist {
		input = append(input, k+"=ambient-leak")
	}
	// A bare-form blocklisted entry must also be stripped.
	if len(hermeticEnvBlocklist) > 0 {
		input = append(input, hermeticEnvBlocklist[0])
	}
	// Unrelated vars must survive.
	input = append(input,
		"PATH=/usr/local/bin:/usr/bin",
		"HOME=/tmp/fake-home",
		"OCM_NOT_CONFIG_SOMETHING=keep",
		"OCM_CONFIG_DERIVED_LOOKALIKE=keep-this", // not in blocklist, must stay
	)

	scrubbed := scrubSubprocessEnv(input)
	got := envMap(scrubbed)

	// Every blocklisted var must be absent.
	for _, k := range hermeticEnvBlocklist {
		if _, ok := got[k]; ok {
			t.Errorf("scrubSubprocessEnv left blocklisted env var %q in result: %v", k, scrubbed)
		}
	}

	// Unrelated vars must be preserved exactly.
	for _, kv := range []string{
		"PATH=/usr/local/bin:/usr/bin",
		"HOME=/tmp/fake-home",
		"OCM_NOT_CONFIG_SOMETHING=keep",
		"OCM_CONFIG_DERIVED_LOOKALIKE=keep-this",
	} {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed expected kv %q", kv)
		}
		gotValue, present := got[key]
		if !present {
			t.Errorf("scrubSubprocessEnv dropped unrelated env var %q", key)
			continue
		}
		if gotValue != value {
			t.Errorf("scrubSubprocessEnv mutated value for %q: got %q, want %q", key, gotValue, value)
		}
	}
}

// TestScrubSubprocessEnvPreservesAllNonBlocklisted asserts that scrubbing a
// realistic env slice only removes blocklisted keys and leaves the relative
// order of the remaining entries intact.
func TestScrubSubprocessEnvPreservesAllNonBlocklisted(t *testing.T) {
	input := []string{
		"PATH=/usr/bin",
		"OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true",
		"HOME=/tmp/home",
		"USER=tester",
		"OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=false", // duplicate, both stripped
		"LANG=C",
	}
	scrubbed := scrubSubprocessEnv(input)

	want := []string{
		"PATH=/usr/bin",
		"HOME=/tmp/home",
		"USER=tester",
		"LANG=C",
	}
	if len(scrubbed) != len(want) {
		t.Fatalf("scrubSubprocessEnv length = %d, want %d (got %v)", len(scrubbed), len(want), scrubbed)
	}
	for i, kv := range want {
		if scrubbed[i] != kv {
			t.Errorf("scrubSubprocessEnv[%d] = %q, want %q (full: %v)", i, scrubbed[i], kv, scrubbed)
		}
	}
}

// TestScrubSubprocessEnvEmptyAndNoop asserts the helper handles empty input and
// input with nothing to scrub without mutating beyond a copy.
func TestScrubSubprocessEnvEmptyAndNoop(t *testing.T) {
	if got := scrubSubprocessEnv(nil); len(got) != 0 {
		t.Errorf("scrubSubprocessEnv(nil) = %v, want empty slice", got)
	}

	input := []string{"PATH=/usr/bin", "HOME=/tmp"}
	scrubbed := scrubSubprocessEnv(input)
	if len(scrubbed) != len(input) {
		t.Fatalf("scrubSubprocessEnv noop length = %d, want %d", len(scrubbed), len(input))
	}
	for i, kv := range input {
		if scrubbed[i] != kv {
			t.Errorf("scrubSubprocessEnv noop[%d] = %q, want %q", i, scrubbed[i], kv)
		}
	}
}

// TestHermeticEnvBlocklistContainsUseEnvFallback asserts the env-proxy
// fallback knob remains in the blocklist, guarding the hermetic contract.
func TestHermeticEnvBlocklistContainsUseEnvFallback(t *testing.T) {
	want := "OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK"
	for _, k := range hermeticEnvBlocklist {
		if k == want {
			return
		}
	}
	blocklisted := append([]string(nil), hermeticEnvBlocklist...)
	sort.Strings(blocklisted)
	t.Errorf("hermeticEnvBlocklist missing %q; current blocklist: %v", want, blocklisted)
}

// TestScrubParentConfigEnvRestoresBlocklistedVars exercises the parent-side
// scrub-and-restore helper (scrubParentConfigEnv) that loadEffectiveSubprocessConfig
// uses to keep ambient OCM_CONFIG_* values out of the hermetic config.Load path.
//
// It sets an ambient blocklisted variable (OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK),
// takes the scrub lock the harness uses for the chdir+scrub window, invokes the
// helper, asserts the variable is absent from the process environment for the
// duration the load would run, then asserts the original value is restored once
// the restore callback returns. The original process environment is always
// restored via t.Cleanup, even on failure, so the test cannot leak state into
// later tests in this package.
func TestScrubParentConfigEnvRestoresBlocklistedVars(t *testing.T) {
	const sentinel = "ambient-from-runner"

	// Snapshot the original value of every blocklisted var so the test can
	// return the process to its prior state regardless of outcome.
	originals := make(map[string]string, len(hermeticEnvBlocklist))
	for _, k := range hermeticEnvBlocklist {
		originals[k] = os.Getenv(k)
	}
	t.Cleanup(func() {
		for _, k := range hermeticEnvBlocklist {
			if v, ok := originals[k]; ok && v != "" {
				_ = os.Setenv(k, v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	})

	// Seed an ambient value for the primary blocklisted knob and any others
	// so the scrub has something to remove and restore.
	for _, k := range hermeticEnvBlocklist {
		if err := os.Setenv(k, sentinel); err != nil {
			t.Fatalf("os.Setenv(%q, %q): %v", k, sentinel, err)
		}
	}

	// The scrub contract requires callers to hold subprocessChdirMu across the
	// scrub and restore, matching how loadEffectiveSubprocessConfig uses it.
	subprocessChdirMu.Lock()
	defer subprocessChdirMu.Unlock()

	restore := scrubParentConfigEnv()

	// During the load window the helper is responsible for, every blocklisted
	// variable must be absent from the process environment so applyEnvOverrides
	// cannot read an ambient runner value.
	for _, k := range hermeticEnvBlocklist {
		if got := os.Getenv(k); got != "" {
			t.Errorf("scrubParentConfigEnv left %q set to %q during load window; want absent", k, got)
		}
	}

	// Restoring must re-apply the prior (sentinel) value for every blocklisted
	// variable that was set before the scrub.
	restore()
	for _, k := range hermeticEnvBlocklist {
		if got := os.Getenv(k); got != sentinel {
			t.Errorf("after restore, %q = %q; want %q", k, got, sentinel)
		}
	}
}
