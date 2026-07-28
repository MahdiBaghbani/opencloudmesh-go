// Package repos provides shared persistence backend lists and test open helpers.
package repos

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	platformrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// AllBackends returns every supported persistence backend name.
func AllBackends() []string {
	return []string{
		config.BackendMemory,
		config.BackendJSON,
		config.BackendSQLite,
		config.BackendMirror,
	}
}

// DurableBackends returns persistence backends that require data_dir.
// It is every AllBackends entry except in-memory storage.
func DurableBackends() []string {
	var out []string

	for _, backend := range AllBackends() {
		if backend == config.BackendMemory {
			continue
		}

		out = append(out, backend)
	}

	return out
}

// TestRepo opens a *repos.Repos for contract and adapter tests.
type TestRepo struct {
	Name string
	Open func(*testing.T) *platformrepos.Repos
}

// OpenTestRepos returns every AllBackends entry with its test open helper.
func OpenTestRepos() []TestRepo {
	all := AllBackends()

	repos := make([]TestRepo, 0, len(all))
	for _, name := range all {
		repos = append(repos, TestRepo{Name: name, Open: openForBackend(name)})
	}

	return repos
}

func openForBackend(name string) func(*testing.T) *platformrepos.Repos {
	switch name {
	case config.BackendMemory:
		return OpenMemory
	case config.BackendJSON:
		return OpenJSON
	case config.BackendSQLite:
		return func(t *testing.T) *platformrepos.Repos {
			return OpenDurable(t, context.Background(), config.BackendSQLite)
		}
	case config.BackendMirror:
		return func(t *testing.T) *platformrepos.Repos {
			return OpenDurable(t, context.Background(), config.BackendMirror)
		}
	default:
		panic("testsupport/repos: no Open helper for backend " + name)
	}
}

// OpenMemory opens an in-memory repos bundle for tests.
func OpenMemory(t *testing.T) *platformrepos.Repos {
	t.Helper()

	r, err := platformrepos.New(context.Background(), config.PersistenceConfig{
		Backend: config.BackendMemory,
	})
	if err != nil {
		t.Fatalf("repos.New(memory): %v", err)
	}

	return r
}

// OpenJSON opens a JSON-backed repos bundle in a temp directory.
func OpenJSON(t *testing.T) *platformrepos.Repos {
	t.Helper()

	r, err := platformrepos.New(context.Background(), config.PersistenceConfig{
		Backend: config.BackendJSON,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repos.New(json): %v", err)
	}

	return r
}

// OpenDurable opens a durable repos bundle for the given backend in a temp dir.
func OpenDurable(t *testing.T, ctx context.Context, backend string) *platformrepos.Repos {
	t.Helper()

	r, err := platformrepos.New(ctx, config.PersistenceConfig{
		Backend: backend,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repos.New(%s): %v", backend, err)
	}

	return r
}
