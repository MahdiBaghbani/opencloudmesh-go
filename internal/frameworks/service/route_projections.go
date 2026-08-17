// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

// DerivedMountSpecs projects coarse mount subtrees from Routes(opts).
func DerivedMountSpecs(opts RouteOpts) []DerivedRouteGroup {
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

		if pathMatchesRoute(path, row.FullPath, row.MatchExact) {
			return sessionAuthRequired(row.SessionPolicy, opts)
		}
	}

	for _, row := range rows {
		if row.AtHostRoot || row.Synthetic {
			continue
		}

		if pathMatchesRoute(path, row.FullPath, row.MatchExact) {
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

func pathMatchesRoute(path, pattern string, matchExact bool) bool {
	if matchExact {
		if path == pattern {
			return true
		}

		if before, paramRest, ok := strings.Cut(pattern, "{"); ok && strings.HasSuffix(paramRest, "}") {
			prefix := strings.TrimSuffix(before, "/")
			if !strings.HasPrefix(path, prefix+"/") {
				return false
			}

			remainder := path[len(prefix)+1:]
			if remainder == "" || strings.Contains(remainder, "/") {
				return false
			}

			return true
		}

		return false
	}

	if path == pattern {
		return true
	}

	if before, ok := strings.CutSuffix(pattern, "/*"); ok {
		prefix := before

		return pathMatchesPrefix(path, prefix)
	}

	if before, _, ok := strings.Cut(pattern, "{"); ok {
		prefix := strings.TrimSuffix(before, "/")

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
