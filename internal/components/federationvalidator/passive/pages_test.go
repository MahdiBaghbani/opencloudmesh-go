// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/html"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
)

func newStartPageTestRouter(t *testing.T, h *Handler) chi.Router {
	t.Helper()

	h.SetCaps(catalog.FullCaps())

	r := chi.NewRouter()
	MountStartPage(r, h)
	r.Method(http.MethodPost, RouteStartCreateSession, http.HandlerFunc(h.HandleStart))

	return r
}

func inputTypeByName(t *testing.T, raw, name string) string {
	t.Helper()

	doc, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse html: %v", err)
	}

	var typ string

	var walk func(*html.Node)

	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var gotName, gotType string

			for _, attr := range n.Attr {
				switch attr.Key {
				case "name":
					gotName = attr.Val
				case "type":
					gotType = attr.Val
				}
			}

			if gotName == name {
				typ = gotType
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)

	return typ
}

func TestHandleStartPage_RendersForm(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	newStartPageTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}

	body := rec.Body.String()

	want := []string{
		`id="start-form"`,
		`method="post"`,
		`action="/validator/start"`,
		`name="target"`,
		`name="optInStats"`,
		`name="optInPermanent"`,
		`name="optInActive"`,
		`id="opt-in-active-block"`,
	}
	for _, fragment := range want {
		if !strings.Contains(body, fragment) {
			t.Fatalf("start page missing %q", fragment)
		}
	}

	if got := inputTypeByName(t, body, "optInActive"); got != "checkbox" {
		t.Fatalf("optInActive type = %q, want checkbox", got)
	}
}

func TestHandleStartPage_ExternalBasePath(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil)
	h.SetExternalBasePath("/ocm")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	h.HandleStartPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), `action="/ocm/validator/start"`) {
		t.Fatalf("start page missing prefixed form action: %s", rec.Body.String())
	}
}

func TestHandleStartPage_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(nil, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	h.HandleStartPage(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHandleStartPage_CoexistsWithCreateSession(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	router := newStartPageTestRouter(t, h)

	getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getRec.Code)
	}

	form := url.Values{}
	form.Set("target", "https://peer.example")
	form.Set("optInStats", "true")
	form.Set("optInPermanent", "true")
	form.Set("optInActive", "true")

	postReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		RouteStartCreateSession,
		strings.NewReader(form.Encode()),
	)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201 body %s", postRec.Code, postRec.Body.String())
	}

	var created startCreateResponse
	if err := json.NewDecoder(postRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if created.ID == "" || !created.OptInStats || !created.OptInPermanent {
		t.Fatalf("create echo = %+v", created)
	}
}

func TestHandleStart_FormURLEncodedOptInActive(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	allowActiveExtend(h)

	form := url.Values{}
	form.Set("target", "https://peer.example")
	form.Set("optInActive", "true")

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		RouteStartCreateSession,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
	}

	created := decodeCreateEcho(t, rec)

	row, err := store.GetTestRun(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !row.OptInActive {
		t.Fatal("optInActive unset after form start")
	}
}

func TestHandleStart_FormURLEncodedUnknownField(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	form := url.Values{}
	form.Set("target", "https://peer.example")
	form.Set("contribute", "1")

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		RouteStartCreateSession,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	assertJSONError(t, rec, "invalid_request")
}

func TestHandleStart_FormURLEncodedOCMIDTarget(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	form := url.Values{}
	form.Set("target", "alice@peer.example")

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		RouteStartCreateSession,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
	}
}
