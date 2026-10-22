//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.auth nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// routeTest describes one request against a web handler and what the browser
// should get back.
type routeTest struct {
	method   string // defaults to GET
	external string // the path the browser requested
	internal string // the path whawty-auth receives, if a proxy rewrites it
	body     string // request body
	status   int
	location string // where the browser ends up after resolving the Location header
	ctype    string // expected prefix of the Content-Type header
	contains string // expected substring of the response body
}

func runRouteTests(t *testing.T, h http.Handler, tests []routeTest) {
	t.Helper()
	for _, tc := range tests {
		method := tc.method
		if method == "" {
			method = http.MethodGet
		}
		internal := tc.internal
		if internal == "" {
			internal = tc.external
		}
		req := httptest.NewRequest(method, internal, strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		name := method + " " + tc.external
		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.status)
			continue
		}
		if tc.location != "" {
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Errorf("%s: invalid Location header: %v", name, err)
				continue
			}
			base, err := url.Parse(tc.external)
			if err != nil {
				t.Fatalf("%s: invalid test URL: %v", name, err)
			}
			got := base.ResolveReference(loc).Path
			if got != tc.location {
				t.Errorf("%s: redirects to %q (Location: %q), want %q", name, got, loc, tc.location)
			}
		}
		if ct := rec.Header().Get("Content-Type"); tc.ctype != "" && !strings.HasPrefix(ct, tc.ctype) {
			t.Errorf("%s: Content-Type = %q, want %q", name, ct, tc.ctype)
		}
		if tc.contains != "" && !strings.Contains(rec.Body.String(), tc.contains) {
			t.Errorf("%s: body does not contain %q", name, tc.contains)
		}
	}
}

func TestNormalizeBasePath(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"/":                 "",
		"  ":                "",
		"//":                "",
		"/..":               "",
		"/auth":             "/auth",
		"/auth/":            "/auth",
		"auth":              "/auth",
		" /auth ":           "/auth",
		"//auth//":          "/auth",
		"/./auth":           "/auth",
		"/x/../auth":        "/auth",
		"/../auth":          "/auth",
		"/apps/whawty-auth": "/apps/whawty-auth",
		"/my auth":          "/my auth",
	} {
		if got := normalizeBasePath(in); got != want {
			t.Errorf("normalizeBasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWithBasePath(t *testing.T) {
	// the inner handler echoes the path it receives
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "path="+r.URL.Path) //nolint:errcheck
	})

	runRouteTests(t, withBasePath(echo, ""), []routeTest{
		{external: "/", status: http.StatusOK, contains: "path=/"},
		{external: "/api/list", status: http.StatusOK, contains: "path=/api/list"},
	})
	runRouteTests(t, withBasePath(echo, "/auth"), []routeTest{
		{external: "/auth", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
		{external: "/auth/", status: http.StatusOK, contains: "path=/"},
		{external: "/auth/api/list", status: http.StatusOK, contains: "path=/api/list"},
		{external: "/", status: http.StatusNotFound},
		{external: "/api/list", status: http.StatusNotFound},
		{external: "/authx", status: http.StatusNotFound},
		{external: "/authx/api/list", status: http.StatusNotFound},
	})
	runRouteTests(t, withBasePath(echo, "/my auth"), []routeTest{
		{external: "/my%20auth", status: http.StatusTemporaryRedirect, location: "/my auth/admin/"},
		{external: "/my%20auth/api/list", status: http.StatusOK, contains: "path=/api/list"},
	})
	rec := httptest.NewRecorder()
	withBasePath(echo, "/my auth").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/my%20auth", nil))
	if loc := rec.Header().Get("Location"); loc != "my%20auth/admin/" {
		t.Errorf("Location header is not properly escaped: %q", loc)
	}
	runRouteTests(t, withBasePath(echo, "/apps/auth"), []routeTest{
		{external: "/apps/auth", status: http.StatusTemporaryRedirect, location: "/apps/auth/admin/"},
		{external: "/apps/auth/api/list", status: http.StatusOK, contains: "path=/api/list"},
		{external: "/apps/api/list", status: http.StatusNotFound},
	})
}

// newTestWebHandler returns the real web handler. The tests below only send
// API requests which fail before the store is used, so no store is needed.
func newTestWebHandler(t *testing.T, basePath string) http.Handler {
	t.Helper()
	h, err := newWebHandler(nil, normalizeBasePath(basePath))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWebHandlerRoutes(t *testing.T) {
	const badRequest = "Error parsing JSON"

	runRouteTests(t, newTestWebHandler(t, ""), []routeTest{
		{external: "/", status: http.StatusTemporaryRedirect, location: "/admin/"},
		{external: "/admin", status: http.StatusTemporaryRedirect, location: "/admin/"},
		{external: "/admin/", status: http.StatusOK, contains: "<html"},
		{method: http.MethodPost, external: "/api/authenticate", body: "x", status: http.StatusBadRequest, contains: badRequest},
		{external: "/nope", status: http.StatusNotFound},
	})

	for _, bp := range []string{"/auth", "/auth/"} {
		runRouteTests(t, newTestWebHandler(t, bp), []routeTest{
			{external: "/auth", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
			{external: "/auth/", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
			{external: "/auth/admin", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
			{external: "/auth/admin/", status: http.StatusOK, contains: "<html"},
			{external: "/auth/admin/index.html", status: http.StatusMovedPermanently, location: "/auth/admin/"},
			{method: http.MethodPost, external: "/auth/api/authenticate", body: "x", status: http.StatusBadRequest, contains: badRequest},
			{external: "/", status: http.StatusNotFound},
			{external: "/admin/", status: http.StatusNotFound},
			{method: http.MethodPost, external: "/api/authenticate", body: "x", status: http.StatusNotFound},
			{external: "/auth/nope", status: http.StatusNotFound},
		})
	}

	runRouteTests(t, newTestWebHandler(t, "/apps/whawty-auth"), []routeTest{
		{external: "/apps/whawty-auth", status: http.StatusTemporaryRedirect, location: "/apps/whawty-auth/admin/"},
		{external: "/apps/whawty-auth/", status: http.StatusTemporaryRedirect, location: "/apps/whawty-auth/admin/"},
		{external: "/apps/whawty-auth/admin/", status: http.StatusOK, contains: "<html"},
		{method: http.MethodPost, external: "/apps/whawty-auth/api/authenticate", body: "x", status: http.StatusBadRequest, contains: badRequest},
	})
}

// A reverse proxy publishes whawty-auth at /auth/ and strips the prefix,
// whawty-auth itself runs without a base-path.
func TestWebHandlerBehindStrippingProxy(t *testing.T) {
	runRouteTests(t, newTestWebHandler(t, ""), []routeTest{
		{external: "/auth/", internal: "/", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
		{external: "/auth/admin", internal: "/admin", status: http.StatusTemporaryRedirect, location: "/auth/admin/"},
		{external: "/auth/admin/index.html", internal: "/admin/index.html", status: http.StatusMovedPermanently, location: "/auth/admin/"},
		{external: "/auth/admin/", internal: "/admin/", status: http.StatusOK, contains: "<html"},
	})
}
