package store

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// TempDataDir creates an isolated temporary data directory for a store driver
// test and registers its removal with t.Cleanup. The pattern follows
// os.MkdirTemp semantics (a trailing "*" is replaced by a random suffix).
func TempDataDir(t *testing.T, pattern string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		t.Fatalf("create temp data dir: %v", err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("cleanup temp data dir: %v", err)
		}
	})

	return dir
}

// OpenDriver constructs a store driver from cfg and initializes it, failing the
// test on any error. The caller owns the returned driver and is responsible for
// closing it. OpenDriver intentionally does not register a close with t.Cleanup
// so that close/reopen durability tests can manage the driver lifecycle
// explicitly (open, close, reopen from the same cfg).
func OpenDriver(t *testing.T, cfg *store.DriverConfig) store.Driver {
	t.Helper()

	d, err := store.New(cfg)
	if err != nil {
		t.Fatalf("create %s driver: %v", cfg.Driver, err)
	}

	if err := d.Init(context.Background()); err != nil {
		if closeErr := d.Close(); closeErr != nil {
			t.Fatalf("init %s driver: %v (close after init failure: %v)", cfg.Driver, err, closeErr)
		}

		t.Fatalf("init %s driver: %v", cfg.Driver, err)
	}

	return d
}
