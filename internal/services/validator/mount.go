// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)

func mountPlaneARoutes(
	r chi.Router,
	passiveHandler *passive.Handler,
	startRatelimit func(http.Handler) http.Handler,
) {
	start := passive.CreateSessionRouteSpec()
	stop := passive.StopSessionRouteSpec()

	if startRatelimit != nil {
		r.With(startRatelimit).Method(start.Method, start.Pattern, http.HandlerFunc(passiveHandler.HandleStart))
	} else {
		r.Method(start.Method, start.Pattern, http.HandlerFunc(passiveHandler.HandleStart))
	}

	r.Method(stop.Method, stop.Pattern, http.HandlerFunc(passiveHandler.HandleStop))
	r.Method(http.MethodGet, RouteAPIScan, http.HandlerFunc(passiveHandler.HandleScan))
}

func buildStartRatelimit(inputs Inputs, profileName string) (func(http.Handler) http.Handler, error) {
	if profileName == "" {
		return nil, nil //nolint:nilnil // nil middleware means no ratelimit wrapper
	}

	if _, err := interceptors.GetProfileConfig(inputs.InterceptorProfiles, "ratelimit", profileName); err != nil {
		return nil, fmt.Errorf("validator: %w", err)
	}

	bucket, err := passive.CreateSessionRateLimitProfile(inputs.Config)
	if err != nil {
		return nil, fmt.Errorf("validator: start_public ratelimit profile: %w", err)
	}

	mw, err := ratelimit.New(inputs.Ratelimit, bucket, inputs.Log)
	if err != nil {
		return nil, fmt.Errorf("validator: create start ratelimit: %w", err)
	}

	return mw, nil
}
