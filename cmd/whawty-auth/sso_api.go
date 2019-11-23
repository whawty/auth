//
// Copyright (c) 2016 whawty contributors (see AUTHORS file)
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
	"fmt"
	"html"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"
)

func handleSSOReturnLoginForm(w http.ResponseWriter, r *http.Request) {
	baseURI := r.Header.Get("X-BaseURI")
	if baseURI == "" {
		baseURI = "/"
	}

	rip := r.Header.Get("X-Real-IP")
	redir := r.URL.Query().Get("redir")
	wdl.Printf("sso: got request for FORM LOGIN for SSO to %q from %q via %s", redir, rip, r.RemoteAddr)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<meta charset="utf-8" />
<title>Login to Realm %q at %q</title>
<form action="%s?redir=%s" method="post">
	<label for=username>Username:</label>
	<input name=username required><p>
	<label for=password>Password:</label>
	<input type=password name=password required><p>
	<button type=submit>Login (and return to %s)</button>
</form>`, baseURI, "Our Realm", r.Host, html.EscapeString(redir), html.EscapeString(redir))))
}

func handleSSOPostLogin(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	rip := r.Header.Get("X-Real-IP")
	wdl.Printf("sso: got LOGIN for SSO request from %q via %s", rip, r.RemoteAddr)

	user := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if user == "" || password == "" {
		http.Error(w, "Bad Request\nMissing at least one of: username, password", http.StatusBadRequest)
		return
	}

	ok, isAdmin, _, err := store.Authenticate(user, password)
	if err != nil || !ok {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	status, _, session := sessions.Generate(user, isAdmin)
	if status != http.StatusOK {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	splitter := strings.Index(r.Host, ":")
	if splitter == -1 {
		splitter = len(r.Host)
	}
	domain := r.Host[:splitter]
	cookie := http.Cookie{
		Name:    "sso", // TODO
		Value:   session,
		Expires: time.Now().Add(10 * time.Minute), // TODO
		Secure:  true,                             // TODO
		Domain:  domain,
		Path:    "/",
	}
	http.SetCookie(w, &cookie)

	redirect := r.URL.Query().Get("redir")
	if redirect == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("login successful"))
		return
	}
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func handleSSOLogin(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleSSOReturnLoginForm(w, r)
		return
	case http.MethodPost:
		handleSSOPostLogin(store, sessions, w, r)
		return
	default:
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}
}

func handleSSOAuth(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("Host")
	uri := r.Header.Get("X-Original-URI")
	rip := r.Header.Get("X-Real-IP")
	wdl.Printf("sso: got SSO AUTHENTICATE request for %s%s from %q via %s", host, uri, rip, r.RemoteAddr)

	session, err := r.Cookie("sso")
	if err != nil || session.Value == "" {
		http.Error(w, "No authentication", http.StatusUnauthorized)
		return
	}

	status, _, user, _ := sessions.Check(session.Value)
	if status != http.StatusOK {
		// nginx config must redirect to login for 401 for this to work as intended
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	w.Header().Set("User", user)
	w.WriteHeader(http.StatusOK)
}

func runSSOLoginListener(listener *net.TCPListener, store *Store, sessions *webSessionFactory) (err error) {
	mux := http.NewServeMux()
	mux.Handle("/", webHandler{store, sessions, handleSSOLogin})

	server := &http.Server{Handler: mux, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	wl.Printf("sso-login: listening on '%s'", listener.Addr())
	return server.Serve(tcpKeepAliveListener{listener})
}

func runSSOLoginAddr(addr string, store *Store, sessions *webSessionFactory) (err error) {
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runSSOLoginListener(ln.(*net.TCPListener), store, sessions)
}

func runSSOAuthListener(listener *net.TCPListener, store *Store, sessions *webSessionFactory) (err error) {
	mux := http.NewServeMux()
	mux.Handle("/", webHandler{store, sessions, handleSSOAuth})

	server := &http.Server{Handler: mux, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	wl.Printf("sso-auth: listening on '%s'", listener.Addr())
	return server.Serve(tcpKeepAliveListener{listener})
}

func runSSOAuthAddr(addr string, store *Store, sessions *webSessionFactory) (err error) {
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runSSOAuthListener(ln.(*net.TCPListener), store, sessions)
}
