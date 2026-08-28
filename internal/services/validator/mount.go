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

func mountValidatorRoutes(
	r chi.Router,
	passiveHandler *passive.Handler,
	startRatelimit func(http.Handler) http.Handler,
	reverseInviteHandler http.HandlerFunc,
	reverseWaitOpen passive.ReverseWaitOpener,
) {
	mountPlaneARoutes(r, passiveHandler, startRatelimit, reverseWaitOpen)
	passive.MountStartPage(r, passiveHandler)
	r.Method(http.MethodGet, RouteHTMLReport, http.HandlerFunc(passiveHandler.HandleReportHTML))

	if reverseInviteHandler != nil &&
		passiveHandler != nil &&
		passiveHandler.Caps().ReverseInviteAvailable() {
		// Paste shares the start/scan/claim limiter. Invite-guess traffic
		// consumes that IP window and can starve those surfaces; start,
		// scan, and claim can starve paste. That accept-starve tradeoff is
		// explicit: one constructor, one budget. RouteSpec.Middleware is
		// metadata only; this wrap is the mount trigger.
		if startRatelimit != nil {
			r.With(startRatelimit).Method(
				http.MethodPost,
				RouteAPISessionReverseInvite,
				reverseInviteHandler,
			)
		} else {
			r.Method(http.MethodPost, RouteAPISessionReverseInvite, reverseInviteHandler)
		}
	}
}

func mountPlaneARoutes(
	r chi.Router,
	passiveHandler *passive.Handler,
	startRatelimit func(http.Handler) http.Handler,
	reverseWaitOpen passive.ReverseWaitOpener,
) {
	passive.MountPlaneARoutesWithHeal(
		r,
		passiveHandler,
		startRatelimit,
		reverseWaitOpen,
	)
}

// buildStartRatelimit constructs the single IP-keyed public limiter for
// create-session, scan, claim, and paste. GetProfileConfig(scan_public) is
// only a presence check: that parent map is not a limiter bucket (naive
// default 100/60). The nested start_public bucket is 10/60.
func buildStartRatelimit(inputs Inputs, profileName string) (func(http.Handler) http.Handler, error) {
	if profileName == "" {
		return func(next http.Handler) http.Handler { return next }, nil
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
		return nil, fmt.Errorf("validator: create shared public ratelimit: %w", err)
	}

	return mw, nil
}
