//
// Copyright (c) 2016 Christian Pointner <equinox@spreadspace.org>
//               2016 Markus Grüneis <gimpf@gimpf.org>
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
	"net/http"
	_ "net/http/pprof"
	"time"
)

func handleWebAuthenticate(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got AUTHENTICATE request from %s", r.RemoteAddr)

	//	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	// encoder := json.NewEncoder(w)
	// encoder.Encode(respdata)
	fmt.Fprintf(w, "not implemented")
}

func handleWebAdd(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got ADD request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

func handleWebRemove(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got REMOVE request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

func handleWebUpdate(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got UPDATE request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

func handleWebSetAdmin(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got SET_ADMIN request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

func handleWebList(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got LIST request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

func handleWebListFull(store *StoreChan, w http.ResponseWriter, r *http.Request) {
	wdl.Printf("web-api: got LIST_FULL request from %s", r.RemoteAddr)

	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, "not implemented")
}

type webHandler struct {
	store *StoreChan
	H     func(*StoreChan, http.ResponseWriter, *http.Request)
}

func (self webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.H(self.store, w, r)
}

func runWebApi(addr string, store *StoreChan) (err error) {
	http.Handle("/api/authenticate", webHandler{store, handleWebAuthenticate})
	http.Handle("/api/add", webHandler{store, handleWebAdd})
	http.Handle("/api/remove", webHandler{store, handleWebRemove})
	http.Handle("/api/update", webHandler{store, handleWebUpdate})
	http.Handle("/api/set-admin", webHandler{store, handleWebSetAdmin})
	http.Handle("/api/list", webHandler{store, handleWebList})
	http.Handle("/api/list-full", webHandler{store, handleWebListFull})

	wl.Printf("web-api: listening on '%s'", addr)
	server := &http.Server{Addr: addr, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	return server.ListenAndServe()
}
