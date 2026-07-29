package ocm

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peer"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

type routeHandlers struct {
	shares         http.HandlerFunc
	inviteAccepted http.HandlerFunc
	token          http.HandlerFunc
}

func mountProtocolRoutes(
	r chi.Router,
	opts service.RouteOpts,
	inputs Inputs,
	handlers routeHandlers,
	peerResolver *peer.Resolver,
) error {
	for _, row := range protocolPostRows(opts) {
		handler, err := handlerForRow(row, handlers)
		if err != nil {
			return err
		}

		middlewares, err := middlewaresForRow(row, inputs, peerResolver)
		if err != nil {
			return err
		}

		r.With(middlewares...).Method(row.Method, row.Pattern, handler)
	}

	return nil
}

// mountJWKSRoute mounts the local OCM JWKS route (GET /jwks) directly. It is
// public and unauthenticated, so it bypasses the POST HTTPSig/peer-resolution
// middleware chain used by mountProtocolRoutes.
func mountJWKSRoute(r chi.Router, inputs Inputs) {
	r.Get(RouteJWKS, newJWKSHandler(inputs.KeyManager).ServeHTTP)
}

func protocolPostRows(opts service.RouteOpts) []service.RouteRow {
	rows := service.DerivedRouteInventory(opts)

	out := make([]service.RouteRow, 0, len(rows))
	for _, row := range rows {
		if row.Service != "ocm" || row.Method != http.MethodPost ||
			row.SurfaceClass != service.SurfaceProtocol || row.Synthetic {
			continue
		}

		out = append(out, row)
	}

	return out
}

func handlerForRow(row service.RouteRow, handlers routeHandlers) (http.HandlerFunc, error) {
	switch row.ID {
	case "ocm-shares":
		return handlers.shares, nil
	case "ocm-invite-accepted":
		return handlers.inviteAccepted, nil
	case service.RouteIDOCMToken:
		return handlers.token, nil
	default:
		return nil, fmt.Errorf("ocm: no handler for route row %q", row.ID)
	}
}

func middlewaresForRow(
	row service.RouteRow,
	inputs Inputs,
	peerResolver *peer.Resolver,
) ([]func(http.Handler) http.Handler, error) {
	var middlewares []func(http.Handler) http.Handler

	if row.BodyLimitBytes <= 0 {
		return nil, fmt.Errorf("ocm: route %q missing body limit", row.ID)
	}

	middlewares = append(middlewares, enforceOCMBodyLimit(row.BodyLimitBytes))

	sig := inputs.SignatureMiddleware

	switch row.PeerResolution {
	case service.PeerResolutionShares:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveSharesRequest))
	case service.PeerResolutionInviteAccepted:
		// /invite-accepted requires signature verification and peer resolution.
		// This covers the invite-acceptance-specific requirement and the sender-side
		// verify-any-signature requirement. Admission follows Applicability rules 3
		// and 4 conditionally on must-use-http-sig.
		// See https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L382-L386
		// See https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L439-L443
		// See https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L796-L812
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveInviteAcceptedRequest))
	case service.PeerResolutionToken:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveTokenRequest))
	default:
		return nil, fmt.Errorf("ocm: route %q missing peer resolution metadata", row.ID)
	}

	return middlewares, nil
}

func enforceOCMBodyLimit(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
