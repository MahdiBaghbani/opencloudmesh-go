package service

import (
	"strings"
)

// DerivedAuthRows projects session auth rows from Routes(opts).
func DerivedAuthRows(opts RouteOpts) []AuthRow {
	rows := Routes(opts)
	out := make([]AuthRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, AuthRow{
			FullPath:      row.FullPath,
			SessionPolicy: row.SessionPolicy,
			AtHostRoot:    row.AtHostRoot,
			Synthetic:     row.Synthetic,
		})
	}
	return out
}

// DerivedRouteGroup is a coarse mount subtree projection for route consumers.
type DerivedRouteGroup struct {
	Name         string
	PathPrefix   string
	RequiresAuth bool
	AtHostRoot   bool
}

// DerivedRouteGroups projects coarse route groups from Routes(opts).
func DerivedRouteGroups(opts RouteOpts) []DerivedRouteGroup {
	rows := Routes(opts)
	out := make([]DerivedRouteGroup, 0, len(rows))
	for _, row := range rows {
		if row.AtHostRoot && !row.Synthetic {
			out = append(out, DerivedRouteGroup{
				Name:         row.ID,
				PathPrefix:   row.FullPath,
				RequiresAuth: sessionAuthRequired(row.SessionPolicy, opts),
				AtHostRoot:   true,
			})
			continue
		}
		if row.Synthetic && !row.AtHostRoot {
			out = append(out, DerivedRouteGroup{
				Name:         row.Service,
				PathPrefix:   row.FullPath,
				RequiresAuth: sessionAuthRequired(row.SessionPolicy, opts),
				AtHostRoot:   false,
			})
		}
	}
	return out
}

// DerivedRouteInventory returns active product route rows (non-synthetic).
func DerivedRouteInventory(opts RouteOpts) []RouteRow {
	rows := Routes(opts)
	out := make([]RouteRow, 0, len(rows))
	for _, row := range rows {
		if row.Synthetic {
			continue
		}
		out = append(out, row)
	}
	return out
}

// SessionAuthChecker caches route rows for hot-path session auth lookups.
type SessionAuthChecker struct {
	opts RouteOpts
	rows []RouteRow
}

// NewSessionAuthChecker builds a checker from Routes(opts) once at router setup.
func NewSessionAuthChecker(opts RouteOpts) *SessionAuthChecker {
	return &SessionAuthChecker{
		opts: opts,
		rows: Routes(opts),
	}
}

// Required reports whether the session gate requires auth for path.
func (c *SessionAuthChecker) Required(path string) bool {
	return sessionAuthRequiredForRows(path, c.rows, c.opts)
}

// SessionAuthRequiredForPath reports whether the session gate requires auth.
func SessionAuthRequiredForPath(path string, opts RouteOpts) bool {
	return sessionAuthRequiredForRows(path, Routes(opts), opts)
}

func sessionAuthRequiredForRows(path string, rows []RouteRow, opts RouteOpts) bool {
	for _, row := range rows {
		if !row.AtHostRoot || row.Synthetic {
			continue
		}
		if pathMatchesRoute(path, row.FullPath) {
			return sessionAuthRequired(row.SessionPolicy, opts)
		}
	}

	for _, row := range rows {
		if row.AtHostRoot || row.Synthetic {
			continue
		}
		if pathMatchesRoute(path, row.FullPath) {
			return sessionAuthRequired(row.SessionPolicy, opts)
		}
	}

	for _, row := range rows {
		if !row.Synthetic {
			continue
		}
		if pathMatchesPrefix(path, row.FullPath) {
			return sessionAuthRequired(row.SessionPolicy, opts)
		}
	}

	return true
}

func pathMatchesRoute(path, pattern string) bool {
	if path == pattern {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return pathMatchesPrefix(path, prefix)
	}
	if idx := strings.Index(pattern, "{"); idx >= 0 {
		prefix := strings.TrimSuffix(pattern[:idx], "/")
		return pathMatchesPrefix(path, prefix)
	}
	return pathMatchesPrefix(path, pattern)
}

func pathMatchesPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		if path[len(prefix)] == '/' {
			return true
		}
	}
	return false
}
