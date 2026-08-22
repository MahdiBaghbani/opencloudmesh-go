// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwksprobe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripDoer struct {
	fn func(*http.Request) (*http.Response, error)
}

func (d roundTripDoer) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	return d.fn(req)
}

func TestGrade_EmptyURIFails(t *testing.T) {
	t.Parallel()

	got := Grade(t.Context(), roundTripDoer{}, "   ")
	if got.Grade != GradeFail || got.ReasonCode != ReasonEmptyURI {
		t.Fatalf("grade=%q reason=%q, want fail/%s", got.Grade, got.ReasonCode, ReasonEmptyURI)
	}
}

func TestGrade_UnreachableAndInvalid(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			http.NotFound(w, r)
		case "/bad":
			w.WriteHeader(http.StatusOK)
			writeBody(t, w, `{`)
		case "/empty":
			w.Header().Set("Content-Type", "application/json")
			writeBody(t, w, `{"keys":[]}`)
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			writeBody(t, w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"YQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := roundTripDoer{fn: func(req *http.Request) (*http.Response, error) {
		return http.DefaultClient.Do(req)
	}}

	cases := []struct {
		name   string
		path   string
		grade  string
		reason string
	}{
		{name: "missing", path: "/missing", grade: GradeFail, reason: ReasonUnreachable},
		{name: "bad json", path: "/bad", grade: GradeFail, reason: ReasonInvalid},
		{name: "empty keys", path: "/empty", grade: GradeFail, reason: ReasonInvalid},
		{name: "ok", path: "/ok", grade: GradePass, reason: ReasonOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := Grade(t.Context(), client, server.URL+tc.path)
			if got.Grade != tc.grade || got.ReasonCode != tc.reason {
				t.Fatalf("grade=%q reason=%q, want %s/%s err=%v", got.Grade, got.ReasonCode, tc.grade, tc.reason, got.Err)
			}
		})
	}
}

func writeBody(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()

	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write body: %v", err)
	}
}

func TestGrade_HonorsConfiguredResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(t, w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"YQ"}]}`)
	}))
	t.Cleanup(server.Close)

	client := limitedDoer{
		roundTripDoer: roundTripDoer{fn: func(req *http.Request) (*http.Response, error) {
			return http.DefaultClient.Do(req)
		}},
		limit: 8,
	}

	got := Grade(t.Context(), client, server.URL)
	if got.Grade != GradeFail || got.ReasonCode != ReasonUnreachable {
		t.Fatalf("grade=%q reason=%q, want fail/%s", got.Grade, got.ReasonCode, ReasonUnreachable)
	}

	if got.Err == nil || !strings.Contains(got.Err.Error(), "too large") {
		t.Fatalf("error = %v, want too large", got.Err)
	}
}

type limitedDoer struct {
	roundTripDoer

	limit int64
}

func (d limitedDoer) MaxResponseBytes() int64 {
	return d.limit
}

func TestGrade_NilClientFails(t *testing.T) {
	t.Parallel()

	got := Grade(t.Context(), nil, "https://peer.example/jwks")
	if got.Grade != GradeFail || got.ReasonCode != ReasonUnreachable {
		t.Fatalf("grade=%q reason=%q, want fail/%s", got.Grade, got.ReasonCode, ReasonUnreachable)
	}

	if !strings.Contains(got.Err.Error(), "nil http client") {
		t.Fatalf("error = %v, want nil client", got.Err)
	}
}
