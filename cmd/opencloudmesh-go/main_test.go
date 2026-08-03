// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package main

import (
	"bytes"
	"testing"
)

func TestPrintVersionTrue(t *testing.T) {
	var buf bytes.Buffer

	done, err := printVersion(true, &buf)
	if err != nil {
		t.Fatalf("printVersion(true) err = %v, want nil", err)
	}

	if !done {
		t.Fatal("printVersion(true) done = false, want true")
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("printVersion(true) wrote %q, want %q", buf.String(), want)
	}
}

func TestPrintVersionFalse(t *testing.T) {
	var buf bytes.Buffer

	done, err := printVersion(false, &buf)
	if err != nil {
		t.Fatalf("printVersion(false) err = %v, want nil", err)
	}

	if done {
		t.Fatal("printVersion(false) done = true, want false")
	}

	if buf.Len() != 0 {
		t.Fatalf("printVersion(false) wrote %q, want nothing", buf.String())
	}
}

func TestRunVersionShortFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"-version"}, &buf)
	if code != 0 {
		t.Fatalf("run(-version) = %d, want 0", code)
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("run(-version) wrote %q, want %q", buf.String(), want)
	}
}

func TestRunVersionLongFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--version"}, &buf)
	if code != 0 {
		t.Fatalf("run(--version) = %d, want 0", code)
	}

	want := version + "\n"
	if buf.String() != want {
		t.Fatalf("run(--version) wrote %q, want %q", buf.String(), want)
	}
}

func TestRunBadFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--nonexistent-flag"}, &buf)
	if code != 2 {
		t.Fatalf("run(--nonexistent-flag) = %d, want 2", code)
	}
}

func TestRunHelpShortFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"-h"}, &buf)
	if code != 0 {
		t.Fatalf("run(-h) = %d, want 0", code)
	}
}

func TestRunHelpLongFlag(t *testing.T) {
	var buf bytes.Buffer

	code := run([]string{"--help"}, &buf)
	if code != 0 {
		t.Fatalf("run(--help) = %d, want 0", code)
	}
}
