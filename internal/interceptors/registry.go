package interceptors

import "sync"

var (
	registryMu sync.RWMutex
	registry   = make(map[string]NewInterceptor)
)

// Register registers an interceptor constructor by name. Called from init().
func Register(name string, fn NewInterceptor) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = fn
}

// Get returns the interceptor constructor for the given name.
func Get(name string) (NewInterceptor, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	fn, ok := registry[name]
	return fn, ok
}

// Names returns a list of all registered interceptor names.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
