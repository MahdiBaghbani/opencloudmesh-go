// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/json"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/mirror"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
)

func TestDriverRegistry(t *testing.T) {
	t.Parallel()

	drivers := store.AvailableDrivers()

	expected := map[string]bool{"json": true, "sqlite": true, "mirror": true}
	for _, d := range drivers {
		if !expected[d] {
			t.Logf("unexpected driver registered: %s", d)
		}

		delete(expected, d)
	}

	for d := range expected {
		t.Errorf("expected driver %q not registered", d)
	}
}

func TestRegister_PanicsOnNilFactory(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil factory")
		}

		if r != "store: nil driver factory" {
			t.Fatalf("panic = %v, want %q", r, "store: nil driver factory")
		}
	}()

	store.Register("ignored-nil-factory", nil)
}

func TestRegister_PanicsOnEmptyName(t *testing.T) {
	t.Parallel()

	factory := func(_ *store.DriverConfig) (store.Driver, error) {
		return nil, errors.New("stub")
	}

	cases := []string{"", "   ", "\t"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic for empty driver name")
				}

				if r != "store: empty driver name" {
					t.Fatalf("panic = %v, want %q", r, "store: empty driver name")
				}
			}()

			store.Register(name, factory)
		})
	}
}

func TestRegister_OverwritesDuplicate(t *testing.T) {
	t.Parallel()

	name := "test-register-overwrite-driver"

	t.Cleanup(func() { store.Unregister(name) })

	used := 0

	store.Register(name, func(_ *store.DriverConfig) (store.Driver, error) {
		used = 1

		return nil, errors.New("factory-1")
	})
	store.Register(name, func(_ *store.DriverConfig) (store.Driver, error) {
		used = 2

		return nil, errors.New("factory-2")
	})

	_, err := store.New(&store.DriverConfig{Driver: name, DataDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error from stub factory")
	}

	if used != 2 {
		t.Fatalf("factory used = %d, want 2 (second registration)", used)
	}
}

func TestUnregister_RemovesDriver(t *testing.T) {
	t.Parallel()

	name := "test-unregister-driver"

	t.Cleanup(func() { store.Unregister(name) })

	store.Register(name, func(_ *store.DriverConfig) (store.Driver, error) {
		return nil, errors.New("stub driver")
	})

	store.Unregister(name)

	_, err := store.New(&store.DriverConfig{Driver: name, DataDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected unknown driver error after Unregister")
	}

	if !strings.Contains(err.Error(), "unknown driver") {
		t.Fatalf("error = %v, want unknown driver", err)
	}

	for _, d := range store.AvailableDrivers() {
		if d == name {
			t.Fatalf("driver %q still listed after Unregister", name)
		}
	}
}
