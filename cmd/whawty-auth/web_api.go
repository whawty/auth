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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	storeLib "github.com/whawty/auth/store"
	"github.com/whawty/auth/ui"
)

func handleWebBasicAuth(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ok, _, _, err := store.Authenticate(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if !ok {
		http.Error(w, "Authentication Failed", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "success") //nolint:errcheck
}

type webAuthenticateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type webAuthenticateResponse struct {
	Session     string    `json:"session,omitempty"`
	Username    string    `json:"username"`
	IsAdmin     bool      `json:"admin"`
	LastChanged time.Time `json:"lastchanged"`
	Error       string    `json:"error,omitempty"`
}

func handleWebAuthenticate(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got AUTHENTICATE request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webAuthenticateRequest{}
	respdata := &webAuthenticateResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Username == "" || reqdata.Password == "" {
		respdata.Error = "empty username or password is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	ok, isAdmin, lastChanged, err := store.Authenticate(reqdata.Username, reqdata.Password)
	if err != nil || !ok {
		respdata.Error = "authentication failed"
		if err != nil {
			respdata.Error = err.Error()
		}
		sendWebResponse(w, http.StatusUnauthorized, respdata)
		return
	}

	respdata.Username = reqdata.Username
	respdata.IsAdmin = isAdmin
	respdata.LastChanged = lastChanged
	var status int
	status, respdata.Error, respdata.Session = sessions.Generate(reqdata.Username, isAdmin)
	sendWebResponse(w, status, respdata)
}

type webAddRequest struct {
	Session  string `json:"session"`
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"admin"`
}

type webAddResponse struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"admin"`
	Error    string `json:"error,omitempty"`
}

func handleWebAdd(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got ADD request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webAddRequest{}
	respdata := &webAddResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session == "" || reqdata.Username == "" || reqdata.Password == "" {
		respdata.Error = "empty session, username or password is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
	if status != http.StatusOK {
		respdata.Error = errorStr
		sendWebResponse(w, status, respdata)
		return
	}

	if !isAdmin {
		respdata.Error = "only admins are allowed to add users"
		sendWebResponse(w, http.StatusForbidden, respdata)
		return
	}

	wdl.Printf("admin '%s' want's to add user '%s' and admin status: %t", username, reqdata.Username, reqdata.IsAdmin)

	if err := store.Add(reqdata.Username, reqdata.Password, reqdata.IsAdmin); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	respdata.Username = reqdata.Username
	respdata.IsAdmin = reqdata.IsAdmin
	sendWebResponse(w, http.StatusOK, respdata)
}

type webRemoveRequest struct {
	Session  string `json:"session"`
	Username string `json:"username"`
}

type webRemoveResponse struct {
	Username string `json:"username"`
	Error    string `json:"error,omitempty"`
}

func handleWebRemove(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got REMOVE request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webRemoveRequest{}
	respdata := &webRemoveResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session == "" || reqdata.Username == "" {
		respdata.Error = "empty session or username is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
	if status != http.StatusOK {
		respdata.Error = errorStr
		sendWebResponse(w, status, respdata)
		return
	}

	if !isAdmin {
		respdata.Error = "only admins are allowed to remove users"
		sendWebResponse(w, http.StatusForbidden, respdata)
		return
	}

	wdl.Printf("admin '%s' want's to remove user '%s'", username, reqdata.Username)

	if err := store.Remove(reqdata.Username); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	respdata.Username = reqdata.Username
	sendWebResponse(w, http.StatusOK, respdata)
}

type webUpdateRequest struct {
	Session     string `json:"session,omitempty"`
	Username    string `json:"username"`
	OldPassword string `json:"oldpassword,omitempty"`
	NewPassword string `json:"newpassword,omitempty"`
}

type webUpdateResponse struct {
	Username string `json:"username"`
	Error    string `json:"error,omitempty"`
}

func handleWebUpdate(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got UPDATE request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webUpdateRequest{}
	respdata := &webUpdateResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Username == "" {
		respdata.Error = "empty username is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session != "" && reqdata.OldPassword == "" {
		if reqdata.NewPassword == "" {
			respdata.Error = "empty newpassword is not allowed when using session based authentication"
			sendWebResponse(w, http.StatusBadRequest, respdata)
			return
		}

		status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
		if status != http.StatusOK {
			respdata.Error = errorStr
			sendWebResponse(w, status, respdata)
			return
		}

		if !isAdmin && username != reqdata.Username {
			respdata.Error = "only admins are allowed to update any users' password"
			sendWebResponse(w, http.StatusForbidden, respdata)
			return
		}
		wdl.Printf("user '%s' want's to update user '%s', using a valid session", username, reqdata.Username)
	} else if reqdata.Session == "" && reqdata.OldPassword != "" {
		ok, _, _, err := store.Authenticate(reqdata.Username, reqdata.OldPassword)
		if err != nil || !ok {
			respdata.Error = "authentication failed"
			if err != nil {
				respdata.Error = err.Error()
			}
			sendWebResponse(w, http.StatusUnauthorized, respdata)
			return
		}
		if reqdata.NewPassword == "" {
			// TODO: return Error if upgrades are disabled since this makes only sense for upgrading password hashes to new parameter-sets
			respdata.Username = reqdata.Username
			sendWebResponse(w, http.StatusOK, respdata)
			return
		}
		wdl.Printf("update user '%s', using current(old) password", reqdata.Username)
	} else {
		respdata.Error = "exactly one of session or old-password must be supplied"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if err := store.Update(reqdata.Username, reqdata.NewPassword); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	respdata.Username = reqdata.Username
	sendWebResponse(w, http.StatusOK, respdata)
}

type webSetAdminRequest struct {
	Session  string `json:"session"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"admin"`
}

type webSetAdminResponse struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"admin"`
	Error    string `json:"error,omitempty"`
}

func handleWebSetAdmin(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got SET_ADMIN request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webSetAdminRequest{}
	respdata := &webSetAdminResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session == "" || reqdata.Username == "" {
		respdata.Error = "empty session or username is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
	if status != http.StatusOK {
		respdata.Error = errorStr
		sendWebResponse(w, status, respdata)
		return
	}

	if !isAdmin {
		respdata.Error = "only admins are allowed to change the admin status of users"
		sendWebResponse(w, http.StatusForbidden, respdata)
		return
	}

	wdl.Printf("admin '%s' want's to set admin status of user '%s' to %t", username, reqdata.Username, reqdata.IsAdmin)

	if err := store.SetAdmin(reqdata.Username, reqdata.IsAdmin); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	respdata.Username = reqdata.Username
	respdata.IsAdmin = reqdata.IsAdmin
	sendWebResponse(w, http.StatusOK, respdata)
}

type webListRequest struct {
	Session string `json:"session"`
}

type webListResponse struct {
	List  storeLib.UserList `json:"list"`
	Error string            `json:"error,omitempty"`
}

func handleWebList(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got LIST request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webListRequest{}
	respdata := &webListResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session == "" {
		respdata.Error = "empty session is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
	if status != http.StatusOK {
		respdata.Error = errorStr
		sendWebResponse(w, status, respdata)
		return
	}

	if !isAdmin {
		respdata.Error = "only admins are allowed to list users"
		sendWebResponse(w, http.StatusForbidden, respdata)
		return
	}

	wdl.Printf("admin '%s' want's to list all supported users", username)

	var err error
	if respdata.List, err = store.List(); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	sendWebResponse(w, http.StatusOK, respdata)
}

type webListFullRequest struct {
	Session string `json:"session"`
}

type webListFullResponse struct {
	List  storeLib.UserListFull `json:"list"`
	Error string                `json:"error,omitempty"`
}

func handleWebListFull(store *Store, sessions *webSessionFactory, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got LIST_FULL request from %s", r.RemoteAddr)

	decoder := json.NewDecoder(r.Body)
	reqdata := &webListFullRequest{}
	respdata := &webListFullResponse{}

	if err := decoder.Decode(reqdata); err != nil {
		respdata.Error = fmt.Sprintf("Error parsing JSON response: %s", err)
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	if reqdata.Session == "" {
		respdata.Error = "empty session is not allowed"
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}

	status, errorStr, username, isAdmin := sessions.Check(reqdata.Session)
	if status != http.StatusOK {
		respdata.Error = errorStr
		sendWebResponse(w, status, respdata)
		return
	}

	if !isAdmin {
		respdata.Error = "only admins are allowed to list users"
		sendWebResponse(w, http.StatusForbidden, respdata)
		return
	}

	wdl.Printf("admin '%s' want's to list all users", username)

	var err error
	if respdata.List, err = store.ListFull(); err != nil {
		respdata.Error = err.Error()
		sendWebResponse(w, http.StatusBadRequest, respdata)
		return
	}
	sendWebResponse(w, http.StatusOK, respdata)
}

func sendWebResponse(w http.ResponseWriter, status int, respdata interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.Encode(respdata) //nolint:errcheck
}

type webHandler struct {
	store    *Store
	sessions *webSessionFactory
	H        func(*Store, *webSessionFactory, http.ResponseWriter, *http.Request)
}

func (h webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.H(h.store, h.sessions, w, r)
}

// This is from golang http package - why is this not exported?
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)                  //nolint:errcheck
	tc.SetKeepAlivePeriod(3 * time.Minute) //nolint:errcheck
	return tc, nil
}

func newWebHandler(store *Store) (mux *http.ServeMux, err error) {
	var sessions *webSessionFactory
	if sessions, err = NewWebSessionFactory(600 * time.Second); err != nil { // TODO: hardcoded value
		return
	}

	mux = http.NewServeMux()
	mux.Handle("/basic-auth", webHandler{store, sessions, handleWebBasicAuth})
	mux.Handle("/api/authenticate", webHandler{store, sessions, handleWebAuthenticate})
	mux.Handle("/api/add", webHandler{store, sessions, handleWebAdd})
	mux.Handle("/api/remove", webHandler{store, sessions, handleWebRemove})
	mux.Handle("/api/update", webHandler{store, sessions, handleWebUpdate})
	mux.Handle("/api/set-admin", webHandler{store, sessions, handleWebSetAdmin})
	mux.Handle("/api/list", webHandler{store, sessions, handleWebList})
	mux.Handle("/api/list-full", webHandler{store, sessions, handleWebListFull})

	mux.Handle("/admin/", http.StripPrefix("/admin/", http.FileServer(http.FS(ui.Assets))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
	return
}

func runHTTPsListener(listener *net.TCPListener, config *httpsConfig, store *Store) (err error) {
	server := &http.Server{ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	if server.Handler, err = newWebHandler(store); err != nil {
		return
	}
	if server.TLSConfig, err = config.TLS.ToGoTLSConfig(); err != nil {
		return
	}
	wl.Printf("web-api: listening on '%s' using TLS", listener.Addr())
	return server.ServeTLS(tcpKeepAliveListener{listener}, "", "")
}

func runHTTPsAddr(addr string, config *httpsConfig, store *Store) error {
	if addr == "" {
		addr = ":https"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runHTTPsListener(listener.(*net.TCPListener), config, store)
}

func runHTTPListener(listener *net.TCPListener, config *httpConfig, store *Store) (err error) {
	server := &http.Server{ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	if server.Handler, err = newWebHandler(store); err != nil {
		return
	}
	wl.Printf("web-api: listening on '%s'", listener.Addr())
	return server.Serve(tcpKeepAliveListener{listener})
}

func runHTTPAddr(addr string, config *httpConfig, store *Store) error {
	if addr == "" {
		addr = ":http"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runHTTPListener(listener.(*net.TCPListener), config, store)
}
