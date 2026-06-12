package ratelimit

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
)

// Inputs holds dependencies for the ratelimit interceptor constructor.
type Inputs struct {
	Cache   cache.Counter
	KeyFunc func(*http.Request) string
}
