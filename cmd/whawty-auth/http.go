//
// Copyright (c) 2016-2026 whawty contributors (see AUTHORS file)
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
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/whawty/auth/ui"
)

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
	addAPIRoutes(mux, store, sessions)
	addUIRoutes(mux, ui.Assets)
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
