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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/whawty/auth/ui"
)

func TestUIRoutes(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":  &fstest.MapFile{Data: []byte("<html>index</html>")},
		"css/app.css": &fstest.MapFile{Data: []byte("body {}")},
		"js/app.js":   &fstest.MapFile{Data: []byte("'use strict';")},
	}
	mux := http.NewServeMux()
	addUIRoutes(mux, assets)

	runRouteTests(t, mux, []routeTest{
		{external: "/", status: http.StatusTemporaryRedirect, location: "/admin/"},
		{external: "/admin", status: http.StatusTemporaryRedirect, location: "/admin/"},
		{external: "/admin/", status: http.StatusOK, ctype: "text/html", contains: "index"},
		{external: "/admin/index.html", status: http.StatusMovedPermanently, location: "/admin/"},
		{external: "/admin/css/app.css", status: http.StatusOK, ctype: "text/css", contains: "body {}"},
		{external: "/admin/js/app.js", status: http.StatusOK, ctype: "text/javascript", contains: "use strict"},
		{external: "/admin/js", status: http.StatusMovedPermanently, location: "/admin/js/"},
		{external: "/admin/missing.js", status: http.StatusNotFound},
		{external: "/index.html", status: http.StatusNotFound},
		{external: "/nope", status: http.StatusNotFound},
		{external: "/adminx", status: http.StatusNotFound},
	})

	// ServeMux redirects paths containing ".." to the cleaned path, which must
	// not lead back into /admin/. The status code of this redirect depends on
	// the Go version (301 before Go 1.26, 307 since), so accept both.
	req := httptest.NewRequest(http.MethodGet, "/admin/../index.html", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("GET /admin/../index.html: status = %d, want a redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/index.html" {
		t.Fatalf("GET /admin/../index.html: Location = %q, want %q", loc, "/index.html")
	}

	for _, p := range []string{"/admin/", "/admin/css/app.css", "/admin/js/app.js", "/admin/missing.js"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		for name, value := range uiSecurityHeaders {
			if got := rec.Header().Get(name); got != value {
				t.Errorf("GET %s: header %s = %q, want %q", p, name, got, value)
			}
		}
	}
}

func TestUIContentSecurityPolicy(t *testing.T) {
	csp := uiSecurityHeaders["Content-Security-Policy"]
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, directive+";") && !strings.HasSuffix(csp, directive) {
			t.Errorf("Content-Security-Policy lacks %q: %s", directive, csp)
		}
	}
	for _, unsafe := range []string{"'unsafe-inline'", "'unsafe-eval'", "*", "http:", "https:", "data:"} {
		if strings.Contains(csp, unsafe) {
			t.Errorf("Content-Security-Policy allows %s: %s", unsafe, csp)
		}
	}
}

var (
	htmlScriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	htmlInlineRe    = regexp.MustCompile(`(?i)<style\b|\s(?:on[a-z]+|style)\s*=`)
)

// The Content-Security-Policy blocks inline scripts, event handler attributes
// and inline styles, so the HTML files of the web interface must not use them.
func TestUIHTMLHasNoInlineCode(t *testing.T) {
	err := fs.WalkDir(ui.Assets, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(name) != ".html" {
			return err
		}
		data, err := fs.ReadFile(ui.Assets, name)
		if err != nil {
			return err
		}
		for _, m := range htmlScriptTagRe.FindAllStringSubmatch(string(data), -1) {
			if !strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) != "" {
				t.Errorf("%s: inline script: %s", name, m[0])
			}
		}
		for _, m := range htmlInlineRe.FindAllString(string(data), -1) {
			t.Errorf("%s: inline style or event handler: %q", name, strings.TrimSpace(m))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	htmlRefRe = regexp.MustCompile(`(?i)\b(?:src|href|action)\s*=\s*["']([^"']*)["']`)
	cssRefRe  = regexp.MustCompile(`url\(\s*["']?([^"')]+)["']?\s*\)`)
	// import ... from '...', export ... from '...' and import '...'
	jsImportRe = regexp.MustCompile(`(?m)^\s*(?:import|export)\s[^'";]*?\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]`)
)

// checkAssetRef makes sure that ref, found in the asset file from, points to
// another file of the web interface. The web interface must work in air-gapped
// environments and below any path prefix, so references to other hosts and
// absolute paths are not allowed.
func checkAssetRef(t *testing.T, from, ref string) {
	t.Helper()
	if strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "#") {
		return
	}
	if strings.HasPrefix(ref, "/") || strings.Contains(ref, ":") {
		t.Errorf("%s: reference %q is not relative to the web interface", from, ref)
		return
	}
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		ref = ref[:i]
	}
	target := path.Join(path.Dir(from), ref)
	if _, err := fs.Stat(ui.Assets, target); err != nil {
		t.Errorf("%s: reference %q points to %q which does not exist", from, ref, target)
	}
}

func TestUIAssetsAreSelfContained(t *testing.T) {
	if _, err := fs.Stat(ui.Assets, "index.html"); err != nil {
		t.Fatal("the web interface has no index.html:", err)
	}

	checked := 0
	err := fs.WalkDir(ui.Assets, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		var re *regexp.Regexp
		switch path.Ext(name) {
		case ".html":
			re = htmlRefRe
		case ".css":
			re = cssRefRe
		case ".js":
			if strings.HasPrefix(name, "vendor/") { // third-party scripts are no modules
				return nil
			}
			re = jsImportRe
		default:
			return nil
		}
		data, err := fs.ReadFile(ui.Assets, name)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			ref := m[1]
			if ref == "" && len(m) > 2 {
				ref = m[2]
			}
			checkAssetRef(t, name, ref)
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("found no references to check, the patterns are probably broken")
	}
}
