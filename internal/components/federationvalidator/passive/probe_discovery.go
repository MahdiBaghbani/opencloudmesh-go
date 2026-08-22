// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/httpsigprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/jwksprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/platformdetect"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/tlsprobe"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type areaGrades struct {
	discovery *string
	tls       *string
	jwks      *string
	httpsig   *string
}

type probeBundle struct {
	grades         areaGrades
	fetch          *discovery.FetchResult
	fetchErr       error
	discoveryURL   string
	scheme         string
	tlsDetail      tlsprobe.ConnectionDetail
	jwks           jwksprobe.Result
	jwksAdvertised bool
	httpsig        httpsigprobe.Result
	jwksURI        string
	platform       string
	apiVersion     string
	attempt        int
}

// GradeDiscovery maps a fresh discovery fetch to the coarse grade contract.
// A missing document or fetch error is an assessed failure.
func GradeDiscovery(result *discovery.FetchResult, fetchErr error) *string {
	effective := effectiveFetchErr(result, fetchErr)
	if effective != nil || result == nil || result.Discovery == nil || !result.Discovery.Enabled {
		return gradePtr(validatorcore.GradeFail)
	}

	if len(result.Discovery.Warnings) > 0 {
		return gradePtr(validatorcore.GradeWarn)
	}

	return gradePtr(validatorcore.GradePass)
}

func (p *ProbeRunner) collectProbeBundle(ctx context.Context, testRunID string) (probeBundle, error) {
	row, err := p.store.GetTestRun(ctx, testRunID)
	if err != nil {
		return probeBundle{}, wrapRetryable(fmt.Errorf("passive probe load session: %w", err))
	}

	bundle := probeBundle{
		discoveryURL: discoveryURLFor(row),
		scheme:       tlsprobe.SchemeFromURL(row.TargetOrigin),
	}

	result, fetchErr := p.discovery.FetchFresh(ctx, row.TargetOrigin)
	bundle.fetch = result
	bundle.fetchErr = effectiveFetchErr(result, fetchErr)
	bundle.grades.discovery = GradeDiscovery(result, fetchErr)

	tlsIn := tlsInputFromFetch(bundle.scheme, result, bundle.fetchErr)
	bundle.tlsDetail = tlsprobe.CaptureTLS(tlsIn)
	bundle.grades.tls = tlsprobe.GradeTLS(bundle.tlsDetail, bundle.scheme, bundle.fetchErr)

	disc := discoveryFrom(result)
	bundle.platform = platformdetect.Detect(providerFrom(disc), headersFrom(result))
	bundle.apiVersion = apiVersionFrom(disc)
	bundle.jwksURI, bundle.jwksAdvertised = advertisedJWKS(disc)
	bundle.jwks = p.gradeJWKS(ctx, bundle.jwksURI, bundle.jwksAdvertised)
	bundle.grades.jwks = gradePtr(bundle.jwks.Grade)
	bundle.httpsig = httpsigprobe.Probe(ctx, httpsigprobe.Input{
		HTTP:   httpsigHTTP(p.http),
		Signer: httpsigSigner(p.signer),
		Origin: row.TargetOrigin,
	})
	bundle.grades.httpsig = gradePtr(bundle.httpsig.Grade)

	return bundle, nil
}

func (p *ProbeRunner) gradeJWKS(ctx context.Context, uri string, advertised bool) jwksprobe.Result {
	if !advertised {
		return jwksprobe.Result{
			Grade:      jwksprobe.GradeWarn,
			ReasonCode: reasonJWKSUnadvertised,
			Headers:    http.Header{},
			Body:       []byte{},
		}
	}

	if strings.TrimSpace(uri) == "" {
		return jwksprobe.Result{
			Grade:      jwksprobe.GradeFail,
			ReasonCode: jwksprobe.ReasonEmptyURI,
			Headers:    http.Header{},
			Body:       []byte{},
		}
	}

	if p.http == nil {
		return jwksprobe.Grade(ctx, nil, uri)
	}

	return jwksprobe.Grade(ctx, p.http, uri)
}

func httpsigHTTP(client *httpclient.ContextClient) httpsigprobe.SignedDoer {
	if client == nil {
		return nil
	}

	return client
}

func httpsigSigner(signer *crypto.RFC9421Signer) httpsigprobe.RequestSigner {
	if signer == nil {
		return nil
	}

	return signer
}

func advertisedJWKS(disc *spec.Discovery) (string, bool) {
	if disc == nil {
		return "", false
	}

	uri := strings.TrimSpace(disc.JwksUri)
	if uri != "" {
		return uri, true
	}

	if disc.IsHTTPSigCapable() {
		return "", true
	}

	return "", false
}

func tlsInputFromFetch(scheme string, result *discovery.FetchResult, fetchErr error) tlsprobe.Input {
	in := tlsprobe.Input{
		Scheme:   scheme,
		FetchErr: fetchErr,
	}

	if result == nil {
		return in
	}

	in.TLSState = result.TLS
	in.ServerIP = result.ServerIP

	return in
}

func effectiveFetchErr(result *discovery.FetchResult, fetchErr error) error {
	if result != nil && result.FetchErr != nil {
		return result.FetchErr
	}

	return fetchErr
}

func discoveryFrom(result *discovery.FetchResult) *spec.Discovery {
	if result == nil {
		return nil
	}

	return result.Discovery
}

func providerFrom(disc *spec.Discovery) string {
	if disc == nil {
		return ""
	}

	return disc.Provider
}

func apiVersionFrom(disc *spec.Discovery) string {
	if disc == nil {
		return ""
	}

	return disc.APIVersion
}

func headersFrom(result *discovery.FetchResult) http.Header {
	if result == nil || result.Headers == nil {
		return http.Header{}
	}

	return result.Headers
}

func discoveryURLFor(row *validatorcore.TestRun) string {
	if row == nil {
		return ""
	}

	if row.DiscoveryURL != "" {
		return row.DiscoveryURL
	}

	return strings.TrimSuffix(row.TargetOrigin, "/") + "/.well-known/ocm"
}

func gradePtr(grade string) *string {
	if grade == "" {
		return nil
	}

	copied := grade

	return &copied
}
