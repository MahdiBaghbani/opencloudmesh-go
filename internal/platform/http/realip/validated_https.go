// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import "context"

type validatedHTTPSKey struct{}

func contextWithValidatedHTTPS(ctx context.Context) context.Context {
	return context.WithValue(ctx, validatedHTTPSKey{}, true)
}

func validatedHTTPSFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(validatedHTTPSKey{}).(bool)

	return ok && v
}
