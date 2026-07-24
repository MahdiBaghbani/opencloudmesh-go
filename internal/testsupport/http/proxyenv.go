package http

import (
	"os"
	"testing"
)

// ProxyEnvKeys lists proxy-related environment variables cleared by ClearProxyEnv.
var ProxyEnvKeys = []string{
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"no_proxy",
}

type proxyEnvSnapshot struct {
	value string
	set   bool
}

// ClearProxyEnv saves and clears proxy-related environment variables so proxy
// and outbound HTTP tests start from a clean baseline. Original values are
// restored when the test finishes.
func ClearProxyEnv(t testing.TB) {
	t.Helper()

	snapshots := make(map[string]proxyEnvSnapshot, len(ProxyEnvKeys))
	for _, key := range ProxyEnvKeys {
		if v, ok := os.LookupEnv(key); ok {
			snapshots[key] = proxyEnvSnapshot{value: v, set: true}
		} else {
			snapshots[key] = proxyEnvSnapshot{set: false}
		}
	}

	t.Cleanup(func() {
		for _, key := range ProxyEnvKeys {
			snap := snapshots[key]
			if snap.set {
				if err := os.Setenv(key, snap.value); err != nil {
					t.Errorf("ClearProxyEnv: restore %s: %v", key, err)
				}
				continue
			}
			if err := os.Unsetenv(key); err != nil {
				t.Errorf("ClearProxyEnv: restore unset %s: %v", key, err)
			}
		}
	})

	for _, key := range ProxyEnvKeys {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("ClearProxyEnv: unset %s: %v", key, err)
		}
	}
}
