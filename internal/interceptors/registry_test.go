package interceptors

import (
	"log/slog"
	"net/http"
	"testing"
)

func TestRegisterAndGet(t *testing.T) {
	// Create a test interceptor
	testMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", "interceptor")
			next.ServeHTTP(w, r)
		})
	}

	testNew := func(conf map[string]any, log *slog.Logger) (Middleware, error) {
		return testMiddleware, nil
	}

	// Register the interceptor
	Register("test-interceptor", testNew)

	// Get should return the registered interceptor
	fn, ok := Get("test-interceptor")
	if !ok {
		t.Fatal("expected to find registered interceptor")
	}
	if fn == nil {
		t.Fatal("expected non-nil interceptor constructor")
	}

	// Construct the middleware
	middleware, err := fn(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if middleware == nil {
		t.Fatal("expected non-nil middleware")
	}
}

func TestGetNotFound(t *testing.T) {
	fn, ok := Get("nonexistent-interceptor")
	if ok {
		t.Fatal("expected not to find nonexistent interceptor")
	}
	if fn != nil {
		t.Fatal("expected nil constructor for nonexistent interceptor")
	}
}

func TestNames(t *testing.T) {
	// Register another test interceptor to ensure Names works
	Register("test-names-interceptor", func(conf map[string]any, log *slog.Logger) (Middleware, error) {
		return nil, nil
	})

	names := Names()
	if len(names) == 0 {
		t.Fatal("expected at least one registered interceptor name")
	}

	// Check that our test interceptor is in the list
	found := false
	for _, name := range names {
		if name == "test-names-interceptor" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find 'test-names-interceptor' in Names()")
	}
}
