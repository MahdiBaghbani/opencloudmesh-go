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
	notifications  http.HandlerFunc
	inviteAccepted http.HandlerFunc
	token          http.HandlerFunc
	requestShare   http.HandlerFunc
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
	case "ocm-notifications":
		return handlers.notifications, nil
	case "ocm-invite-accepted":
		return handlers.inviteAccepted, nil
	case service.RouteIDOCMToken:
		return handlers.token, nil
	case "ocm-request-share":
		return handlers.requestShare, nil
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
	case service.PeerResolutionNone:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignature(nil))
	case service.PeerResolutionShares:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveSharesRequest))
	case service.PeerResolutionInviteAccepted:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveInviteAcceptedRequest))
	case service.PeerResolutionToken:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveTokenRequest))
	case service.PeerResolutionRequestShare:
		middlewares = append(middlewares, sig.VerifyOCMRequestRequireSignatureAndPeer(peerResolver.ResolveRequestShareRequest))
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
